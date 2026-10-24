// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf2socks.h"
#include "bridge/dns.h"
#include "bridge/internal.h"
#include "bridge/socks5.h"
#include "bridge/udp_internal.h"
#include "bridge/udp_relay_registry.h"
#include "core/compat.h"
#include "core/log.h"
#include "core/socket_util.h"
#include "core/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* DNS fast path: shared SOCKS5 UDP channels with rewritten transaction IDs. */

bool bpf2socks_udp_dns_is_candidate(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_udp_client_packet *packet) {
    return config != NULL &&
        config->enable_dns_hijack &&
        packet != NULL &&
        packet->original_dst.port == 53U &&
        (packet->original_dst.family == AF_INET || packet->original_dst.family == AF_INET6);
}

static void release_dns_channel_transactions(struct bpf2socks_udp_state *state, uint32_t channel_index) {
    if (state == NULL || state->dns_table.transactions == NULL) return;
    for (size_t i = 0U; i < state->dns_table.capacity; ++i) {
        struct bpf2socks_dns_transaction *tx = &state->dns_table.transactions[i];
        if (tx->used && tx->channel_index == channel_index) {
            bpf2socks_dns_table_release(&state->dns_table, tx);
        }
    }
}

static void reset_dns_channel_fds(struct bpf2socks_udp_state *state, struct bpf2socks_udp_dns_channel *channel) {
    if (channel == NULL) return;
    if (channel->relay_port_claimed) {
        bpf2socks_udp_relay_port_release(state->relay_registry, channel->relay_port);
        channel->relay_port_claimed = false;
    }
    if (channel->tcp_fd >= 0) bpf2socks_udp_epoll_remove(state, channel->tcp_fd);
    if (channel->udp_fd >= 0) bpf2socks_udp_epoll_remove(state, channel->udp_fd);
    if (channel->tcp_fd >= 0) close(channel->tcp_fd);
    if (channel->udp_fd >= 0) close(channel->udp_fd);
    channel->tcp_fd = -1;
    channel->udp_fd = -1;
    channel->available = false;
    channel->stage = BPF2SOCKS_UDP_DNS_IDLE;
    channel->stage_started_ms = 0U;
    channel->relay_paused = false;
    channel->write_len = 0U;
    channel->write_offset = 0U;
    channel->read_len = 0U;
    memset(&channel->relay_addr, 0, sizeof(channel->relay_addr));
    channel->relay_addr_len = 0U;
    channel->relay_connected = false;
    memset(&channel->control_ref, 0, sizeof(channel->control_ref));
    channel->control_ref.kind = BPF2SOCKS_UDP_FD_DNS_CONTROL;
    channel->control_ref.fd = -1;
    channel->control_ref.dns_channel_index = channel->index;
    memset(&channel->relay_ref, 0, sizeof(channel->relay_ref));
    channel->relay_ref.kind = BPF2SOCKS_UDP_FD_DNS_RELAY;
    channel->relay_ref.fd = -1;
    channel->relay_ref.dns_channel_index = channel->index;
}

void bpf2socks_udp_dns_close_channel(struct bpf2socks_udp_state *state, struct bpf2socks_udp_dns_channel *channel, uint64_t now_ms) {
    if (state == NULL || channel == NULL) return;
    release_dns_channel_transactions(state, channel->index);
    reset_dns_channel_fds(state, channel);
    if (now_ms == 0U) now_ms = bpf2socks_now_ms();
    channel->next_rebuild_ms = now_ms + BPF2SOCKS_DNS_CHANNEL_REBUILD_DELAY_MILLISECONDS;
}

void bpf2socks_udp_dns_expire_transactions(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms) {
    if (state == NULL || worker == NULL || worker->config == NULL) return;
    bool stale_channels[BPF2SOCKS_DNS_CHANNELS_PER_WORKER] = {false};
    size_t expired = bpf2socks_dns_table_expire(
        &state->dns_table,
        now_ms,
        worker->config->dns_transaction_timeout_milliseconds,
        BPF2SOCKS_DNS_MAX_EXPIRE_PER_LOOP,
        stale_channels,
        BPF2SOCKS_DNS_CHANNELS_PER_WORKER);
    worker->udp_stats.dns_transaction_timeouts += (uint64_t)expired;
    for (uint32_t i = 0U; i < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++i) {
        if (!stale_channels[i]) continue;
        ++worker->udp_stats.dns_channel_timeout_rebuilds;
        bpf2socks_udp_dns_close_channel(state, &state->dns_channels[i], now_ms);
    }
}


static int advance_dns_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint32_t events,
    uint64_t now_ms);
void bpf2socks_udp_dns_control_event(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint32_t events,
    uint64_t now_ms) {
    if (channel == NULL || channel->tcp_fd < 0) return;
    if (channel->stage != BPF2SOCKS_UDP_DNS_IDLE && channel->stage != BPF2SOCKS_UDP_DNS_READY) {
        if (advance_dns_channel(state, worker, channel, events, now_ms) < 0) {
            bpf2socks_udp_dns_close_channel(state, channel, now_ms);
        }
        return;
    }
    if (bpf2socks_udp_control_event_is_failure(channel->tcp_fd, events)) {
        bpf2socks_udp_dns_close_channel(state, channel, now_ms);
    }
}

static int open_dns_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint64_t now_ms) {
    if (state == NULL || worker == NULL || channel == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (channel->available && channel->udp_fd >= 0) return 0;
    if (channel->stage != BPF2SOCKS_UDP_DNS_IDLE) {
        errno = EAGAIN;
        return -1;
    }
    if (now_ms == 0U) now_ms = bpf2socks_now_ms();
    if (channel->next_rebuild_ms != 0U && now_ms < channel->next_rebuild_ms) {
        errno = EAGAIN;
        return -1;
    }

    reset_dns_channel_fds(state, channel);
    int tcp_fd = bpf2socks_socks5_connect_nonblock(
        (const struct sockaddr *)&worker->socks_addr,
        worker->socks_addr_len);
    if (tcp_fd < 0) {
        int saved = errno;
        channel->next_rebuild_ms = now_ms + BPF2SOCKS_DNS_CHANNEL_REBUILD_DELAY_MILLISECONDS;
        errno = saved;
        return -1;
    }
    channel->tcp_fd = tcp_fd;
    channel->udp_fd = -1;
    channel->stage = BPF2SOCKS_UDP_DNS_CONNECTING;
    channel->stage_started_ms = now_ms;
    channel->control_ref.kind = BPF2SOCKS_UDP_FD_DNS_CONTROL;
    channel->control_ref.fd = tcp_fd;
    channel->control_ref.session = NULL;
    channel->control_ref.dns_channel_index = channel->index;
    if (bpf2socks_udp_epoll_add_events(state, tcp_fd, &channel->control_ref, EPOLLOUT | EPOLLRDHUP) < 0) {
        int saved = errno;
        close(tcp_fd);
        channel->tcp_fd = -1;
        channel->stage = BPF2SOCKS_UDP_DNS_IDLE;
        channel->next_rebuild_ms = now_ms + BPF2SOCKS_DNS_CHANNEL_REBUILD_DELAY_MILLISECONDS;
        errno = saved;
        return -1;
    }
    errno = EAGAIN;
    return -1;
}

static int finish_dns_channel_connect(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint64_t now_ms) {
    int error = 0;
    socklen_t error_len = sizeof(error);
    if (getsockopt(channel->tcp_fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0) {
        if (error != 0) errno = error;
        return -1;
    }
    channel->write_len = bpf2socks_socks5_build_hello(channel->write_buf, sizeof(channel->write_buf));
    if (channel->write_len == 0U) return -1;
    channel->write_offset = 0U;
    channel->read_len = 0U;
    channel->stage = BPF2SOCKS_UDP_DNS_HELLO_WRITE;
    channel->stage_started_ms = now_ms;
    return advance_dns_channel(state, worker, channel, EPOLLOUT, now_ms);
}

static int dns_channel_do_write(struct bpf2socks_udp_dns_channel *channel) {
    while (channel->write_offset < channel->write_len) {
        ssize_t sent = send(
            channel->tcp_fd,
            channel->write_buf + channel->write_offset,
            channel->write_len - channel->write_offset,
            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (sent <= 0) return -1;
        channel->write_offset += (size_t)sent;
    }
    return 1;
}

static int dns_channel_do_read(struct bpf2socks_udp_dns_channel *channel, size_t expected) {
    while (channel->read_len < expected) {
        ssize_t received = recv(
            channel->tcp_fd,
            channel->read_buf + channel->read_len,
            expected - channel->read_len,
            MSG_DONTWAIT);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (received <= 0) return -1;
        channel->read_len += (size_t)received;
    }
    return 1;
}

static int advance_dns_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint32_t events,
    uint64_t now_ms) {
    if (channel == NULL || channel->tcp_fd < 0) return -1;

    switch (channel->stage) {
        case BPF2SOCKS_UDP_DNS_CONNECTING:
            if ((events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0U) return -1;
            if ((events & EPOLLOUT) == 0U) return 0;
            if (finish_dns_channel_connect(state, worker, channel, now_ms) < 0) return -1;
            return 0;

        case BPF2SOCKS_UDP_DNS_HELLO_WRITE:
            if ((events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0U) return -1;
            if ((events & EPOLLOUT) == 0U) return 0;
            {
                int result = dns_channel_do_write(channel);
                if (result < 0) return -1;
                if (result == 0) return 0;
            }
            channel->stage = BPF2SOCKS_UDP_DNS_HELLO_READ;
            channel->read_len = 0U;
            channel->stage_started_ms = now_ms;
            if (bpf2socks_udp_epoll_modify(
                    state, channel->tcp_fd, &channel->control_ref, EPOLLIN | EPOLLRDHUP) < 0) return -1;
            return 0;

        case BPF2SOCKS_UDP_DNS_HELLO_READ:
            if ((events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0U) return -1;
            if ((events & EPOLLIN) == 0U) return 0;
            {
                int result = dns_channel_do_read(channel, 2U);
                if (result < 0) return -1;
                if (result == 0) return 0;
                if (bpf2socks_socks5_parse_hello_reply(channel->read_buf, channel->read_len) < 0) return -1;
            }
            channel->write_len = bpf2socks_socks5_build_udp_associate_request(
                channel->write_buf, sizeof(channel->write_buf));
            if (channel->write_len == 0U) return -1;
            channel->write_offset = 0U;
            channel->read_len = 0U;
            channel->stage = BPF2SOCKS_UDP_DNS_ASSOC_WRITE;
            channel->stage_started_ms = now_ms;
            if (bpf2socks_udp_epoll_modify(
                    state, channel->tcp_fd, &channel->control_ref, EPOLLOUT | EPOLLRDHUP) < 0) return -1;
            return 0;

        case BPF2SOCKS_UDP_DNS_ASSOC_WRITE:
            if ((events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0U) return -1;
            if ((events & EPOLLOUT) == 0U) return 0;
            {
                int result = dns_channel_do_write(channel);
                if (result < 0) return -1;
                if (result == 0) return 0;
            }
            channel->stage = BPF2SOCKS_UDP_DNS_ASSOC_READ;
            channel->read_len = 0U;
            channel->stage_started_ms = now_ms;
            if (bpf2socks_udp_epoll_modify(
                    state, channel->tcp_fd, &channel->control_ref, EPOLLIN | EPOLLRDHUP) < 0) return -1;
            return 0;

        case BPF2SOCKS_UDP_DNS_ASSOC_READ:
            if ((events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0U) return -1;
            if ((events & EPOLLIN) == 0U) return 0;
            {
                int result = dns_channel_do_read(channel, 4U);
                if (result < 0) return -1;
                if (result == 0) return 0;
            }
            /* ATYP tells the reply's total length; a domain needs its length byte too. */
            {
                size_t total = bpf2socks_socks5_reply_length(channel->read_buf, channel->read_len);
                if (total == 0U) {
                    int r = dns_channel_do_read(channel, 5U);
                    if (r <= 0) return r;
                    total = bpf2socks_socks5_reply_length(channel->read_buf, channel->read_len);
                }
                if (total == SIZE_MAX || total > sizeof(channel->read_buf)) return -1;
                int r = dns_channel_do_read(channel, total);
                if (r <= 0) return r;
            }
            {
                size_t consumed = 0U;
                int parse_result = bpf2socks_socks5_parse_bound_addr(
                    channel->read_buf, channel->read_len, &consumed,
                    &channel->relay_addr, &channel->relay_addr_len);
                if (parse_result != 0) return -1;
            }
            if (bpf2socks_socks5_replace_unspecified_relay(
                    (const struct sockaddr *)&worker->socks_addr,
                    &channel->relay_addr,
                    &channel->relay_addr_len) < 0) return -1;
            uint16_t relay_port = bpf2socks_udp_sockaddr_port(&channel->relay_addr);
            if (bpf2socks_udp_relay_port_needs_claim(worker, relay_port)) {
                if (!bpf2socks_udp_relay_port_claim(worker->udp_relay_registry, relay_port)) {
                    /* Rebuilt after the usual delay; queries use the session path meanwhile. */
                    ++worker->udp_stats.udp_relay_port_collisions;
                    return -1;
                }
                channel->relay_port = relay_port;
                channel->relay_port_claimed = true;
            }
            int udp_fd = socket(
                channel->relay_addr.ss_family,
                SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (udp_fd < 0) return -1;
            bpf2socks_socket_tune_buffers(
                udp_fd,
                worker->config->udp_socket_buffer_size,
                worker->config->udp_socket_buffer_size);
            channel->udp_fd = udp_fd;
            channel->relay_connected = bpf2socks_udp_relay_connect(udp_fd, &channel->relay_addr, channel->relay_addr_len);
            channel->relay_ref.kind = BPF2SOCKS_UDP_FD_DNS_RELAY;
            channel->relay_ref.fd = udp_fd;
            channel->relay_ref.session = NULL;
            channel->relay_ref.dns_channel_index = channel->index;
            if (bpf2socks_udp_epoll_add(state, udp_fd, &channel->relay_ref) < 0) {
                int saved = errno;
                close(udp_fd);
                channel->udp_fd = -1;
                errno = saved;
                return -1;
            }
            channel->stage = BPF2SOCKS_UDP_DNS_READY;
            channel->available = true;
            channel->next_rebuild_ms = 0U;
            channel->stage_started_ms = 0U;
            if (bpf2socks_udp_epoll_modify(
                    state, channel->tcp_fd, &channel->control_ref, EPOLLIN | EPOLLRDHUP) < 0) return -1;
            ++worker->udp_stats.udp_associate_creates;
            return 0;

        default:
            return 0;
    }
}

void bpf2socks_udp_dns_expire_handshakes(
    struct bpf2socks_udp_state *state,
    uint64_t now_ms) {
    for (uint32_t i = 0U; i < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++i) {
        struct bpf2socks_udp_dns_channel *channel = &state->dns_channels[i];
        if (channel->stage == BPF2SOCKS_UDP_DNS_IDLE || channel->stage == BPF2SOCKS_UDP_DNS_READY) continue;
        if (channel->stage_started_ms == 0U) continue;
        if (now_ms - channel->stage_started_ms < BPF2SOCKS_DNS_HANDSHAKE_TIMEOUT_MILLISECONDS) continue;
        bpf2socks_udp_dns_close_channel(state, channel, now_ms);
    }
}

static int ensure_dns_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint64_t now_ms) {
    if (channel != NULL &&
        channel->available &&
        channel->tcp_fd >= 0 &&
        channel->udp_fd >= 0 &&
        bpf2socks_udp_control_fd_is_healthy(channel->tcp_fd)) {
        ++worker->udp_stats.udp_associate_reuses;
        return 0;
    }
    if (channel != NULL && channel->stage != BPF2SOCKS_UDP_DNS_IDLE &&
        channel->stage != BPF2SOCKS_UDP_DNS_READY) {
        errno = EAGAIN;
        return -1;
    }
    if (channel != NULL &&
        (channel->available || channel->tcp_fd >= 0 || channel->udp_fd >= 0)) {
        bpf2socks_udp_dns_close_channel(state, channel, now_ms);
    }
    return open_dns_channel(state, worker, channel, now_ms);
}

static struct bpf2socks_udp_dns_channel *select_dns_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms) {
    if (state == NULL || worker == NULL) return NULL;
    uint32_t start = state->next_dns_channel % BPF2SOCKS_DNS_CHANNELS_PER_WORKER;
    for (uint32_t attempt = 0U; attempt < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++attempt) {
        uint32_t index = (start + attempt) % BPF2SOCKS_DNS_CHANNELS_PER_WORKER;
        struct bpf2socks_udp_dns_channel *channel = &state->dns_channels[index];
        if (ensure_dns_channel(state, worker, channel, now_ms) == 0) {
            state->next_dns_channel = (index + 1U) % BPF2SOCKS_DNS_CHANNELS_PER_WORKER;
            return channel;
        }
    }
    return NULL;
}

int bpf2socks_udp_dns_prepare_query(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_packet *packet,
    const struct bpf2socks_dns_packet_info *info,
    uint64_t now_ms,
    struct bpf2socks_dns_transaction **out_tx,
    uint32_t *out_channel_index,
    struct bpf2socks_udp_msg *out_message) {
    if (state == NULL || worker == NULL || packet == NULL || info == NULL ||
        out_tx == NULL || out_channel_index == NULL || out_message == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_dns_channel *channel = select_dns_channel(state, worker, now_ms);
    if (channel == NULL) return -1;

    bool allocate_from_free_stack = state->dns_table.free_count > 0U;
    struct bpf2socks_dns_transaction *tx = bpf2socks_dns_table_alloc(
        &state->dns_table,
        channel->index,
        info->id,
        info->question_fingerprint,
        now_ms);
    if (tx == NULL) return -1;
    if (allocate_from_free_stack) {
        ++worker->udp_stats.dns_free_stack_allocations;
    } else {
        ++worker->udp_stats.dns_full_table_evictions;
    }

    channel = &state->dns_channels[tx->channel_index];
    if (ensure_dns_channel(state, worker, channel, now_ms) < 0) {
        bpf2socks_dns_table_release(&state->dns_table, tx);
        return -1;
    }

    tx->client_addr = packet->client_addr;
    tx->client_addr_len = packet->client_addr_len;
    tx->original_dst = packet->original_dst;
    tx->token_family = packet->token_family;
    memcpy(tx->token_addr, packet->token_addr, packet->token_family == AF_INET6 ? 16U : 4U);
    tx->connected_udp_token = packet->connected_udp_token;
    tx->original_from_socket = packet->original_from_socket;

    bpf2socks_dns_set_id(packet->payload, packet->payload_len, tx->rewritten_id);
    *out_tx = tx;
    *out_channel_index = tx->channel_index;
    *out_message = (struct bpf2socks_udp_msg){
        .addr = packet->original_dst,
        .payload = packet->payload,
        .payload_len = packet->payload_len,
    };
    return 0;
}

void bpf2socks_udp_dns_flush_outgoing(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_dns_transaction **transactions,
    uint32_t *channel_indices,
    struct bpf2socks_udp_msg *messages,
    unsigned int count) {
    if (state == NULL || worker == NULL || transactions == NULL ||
        channel_indices == NULL || messages == NULL) {
        return;
    }
    for (unsigned int i = 0U; i < count; ++i) {
        if (transactions[i] == NULL) continue;
        uint32_t channel_index = channel_indices[i];
        if (channel_index >= BPF2SOCKS_DNS_CHANNELS_PER_WORKER) {
            bpf2socks_dns_table_release(&state->dns_table, transactions[i]);
            transactions[i] = NULL;
            continue;
        }
        struct bpf2socks_udp_dns_channel *channel = &state->dns_channels[channel_index];
        struct bpf2socks_udp_msg send_messages[BPF2SOCKS_UDP_MAX_BATCH];
        struct bpf2socks_dns_transaction *send_transactions[BPF2SOCKS_UDP_MAX_BATCH];
        unsigned int send_count = 0U;
        for (unsigned int j = i; j < count; ++j) {
            if (transactions[j] == NULL || channel_indices[j] != channel_index) continue;
            send_transactions[send_count] = transactions[j];
            send_messages[send_count++] = messages[j];
            transactions[j] = NULL;
        }
        if (!channel->available || channel->udp_fd < 0) {
            bpf2socks_udp_dns_close_channel(state, channel, bpf2socks_now_ms());
            continue;
        }
        int sent = bpf2socks_socks5_udp_sendmmsg(
            channel->udp_fd,
            bpf2socks_udp_relay_destination(&channel->relay_addr, channel->relay_connected),
            channel->relay_addr_len,
            send_messages,
            send_count);
        if (sent <= 0) {
            ++worker->udp_stats.udp_send_errors;
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                for (unsigned int j = 0U; j < send_count; ++j) {
                    bpf2socks_dns_table_release(&state->dns_table, send_transactions[j]);
                }
            } else {
                bpf2socks_udp_dns_close_channel(state, channel, bpf2socks_now_ms());
            }
            continue;
        }
        worker->udp_stats.udp_packets_to_upstream += (uint64_t)sent;
        worker->udp_stats.udp_copy_sends += (uint64_t)sent;
        if ((unsigned int)sent < send_count) {
            ++worker->udp_stats.udp_send_errors;
            for (unsigned int j = (unsigned int)sent; j < send_count; ++j) {
                bpf2socks_dns_table_release(&state->dns_table, send_transactions[j]);
            }
        }
    }
}

static bool dns_transaction_needs_original_reply_socket(const struct bpf2socks_dns_transaction *tx) {
    if (tx == NULL || tx->connected_udp_token) return false;
    return tx->original_from_socket ||
        tx->original_dst.family == AF_INET ||
        tx->original_dst.family == AF_INET6;
}

static int ensure_dns_raw_reply_socket(struct bpf2socks_udp_state *state, int family) {
    if (state == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (family == AF_INET) {
        if (state->dns_raw4_fd < 0) state->dns_raw4_fd = bpf2socks_udp_raw_reply_socket_create4();
        return state->dns_raw4_fd;
    }
    if (family == AF_INET6) {
        if (state->dns_raw6_fd < 0) state->dns_raw6_fd = bpf2socks_udp_raw_reply_socket_create6();
        return state->dns_raw6_fd;
    }
    errno = EAFNOSUPPORT;
    return -1;
}

static int send_dns_response_with_binding(
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding,
    const struct bpf2socks_udp_msg *message) {
    if (worker == NULL || session == NULL || binding == NULL || message == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (binding->reply_fd >= 0) {
        if (binding->reply_raw) {
            int send_result = binding->original_dst.family == AF_INET6
                ? bpf2socks_udp_raw_send6(binding->reply_fd, session, binding, message->payload, message->payload_len)
                : bpf2socks_udp_raw_send4(binding->reply_fd, session, binding, message->payload, message->payload_len);
            if (send_result < 0) return -1;
            ++worker->udp_stats.udp_packets_to_client;
            ++worker->udp_stats.udp_copy_sends;
            return 0;
        }
        struct bpf2socks_udp_downlink_batch batch;
        bpf2socks_udp_downlink_batch_init(&batch);
        if (bpf2socks_udp_downlink_batch_queue(NULL, &batch, worker, session, binding, message, binding->reply_fd, false) < 0) {
            return -1;
        }
        return bpf2socks_udp_downlink_batch_flush(NULL, &batch, worker);
    }

    int reply_listener_fd = session->client_addr.ss_family == AF_INET6 && worker->udp6_listener_fd >= 0
        ? worker->udp6_listener_fd
        : worker->udp4_listener_fd;
    struct bpf2socks_udp_downlink_batch batch;
    bpf2socks_udp_downlink_batch_init(&batch);
    if (bpf2socks_udp_downlink_batch_queue(NULL, &batch, worker, session, binding, message, reply_listener_fd, true) < 0) {
        return -1;
    }
    return bpf2socks_udp_downlink_batch_flush(NULL, &batch, worker);
}

static int send_dns_response_to_client(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_dns_transaction *tx,
    const struct bpf2socks_udp_msg *message) {
    if (state == NULL || worker == NULL || tx == NULL || message == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_client_session session;
    memset(&session, 0, sizeof(session));
    session.used = true;
    session.client_addr = tx->client_addr;
    session.client_addr_len = tx->client_addr_len;
    session.tcp_fd = -1;
    session.udp_fd = -1;

    struct bpf2socks_udp_reply_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.used = true;
    binding.original_dst = tx->original_dst;
    binding.connected_udp_token = tx->connected_udp_token;
    binding.reply_fd = -1;
    binding.reply_raw = false;
    binding.owner = &session;
    memcpy(binding.token_addr, tx->token_addr, tx->token_family == AF_INET6 ? 16U : 4U);

    if (dns_transaction_needs_original_reply_socket(tx)) {
        int raw_fd = ensure_dns_raw_reply_socket(state, tx->original_dst.family);
        if (raw_fd >= 0) {
            binding.reply_fd = raw_fd;
            binding.reply_raw = true;
            int result = send_dns_response_with_binding(worker, &session, &binding, message);
            /* The kernel never fragments a header-included raw send, so a
             * response larger than the route MTU (a hotspot client behind a
             * 1500 B link) needs a UDP socket that the kernel may fragment. */
            if (result == 0 || errno != EMSGSIZE) return result;
        }

        bool reply_raw = false;
        int reply_fd = bpf2socks_udp_reply_socket_create(&tx->original_dst, &reply_raw);
        if (reply_fd < 0) return -1;
        binding.reply_fd = reply_fd;
        binding.reply_raw = reply_raw;
        int result = send_dns_response_with_binding(worker, &session, &binding, message);
        close(reply_fd);
        return result;
    }

    return send_dns_response_with_binding(worker, &session, &binding, message);
}

void bpf2socks_udp_dns_handle_upstream(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint8_t *upstream_packets) {
    if (state == NULL || worker == NULL || channel == NULL || upstream_packets == NULL ||
        !channel->available || channel->udp_fd < 0) {
        return;
    }
    uint32_t batch = state->batch_size;
    if (state->pending_budget != NULL && bpf2socks_udp_downlink_reserve_slots(state, &batch) < 0) {
        channel->relay_paused = true;
        if (bpf2socks_udp_epoll_modify(
                state, channel->udp_fd, &channel->relay_ref, 0U) < 0) {
            ++worker->udp_stats.udp_send_errors;
        }
        return;
    }
    size_t stride = BPF2SOCKS_UDP_BUFFER_SIZE + BPF2SOCKS_MAX_SOCKS5_UDP_HEADER;

    struct bpf2socks_udp_msg messages[batch];
    memset(messages, 0, sizeof(messages));
    int received = bpf2socks_socks5_udp_recvmmsg(channel->udp_fd, messages, batch, upstream_packets, stride);
    if (received <= 0) {
        if (state->pending_budget != NULL) bpf2socks_udp_downlink_release_reservation(state);
        if (received < 0 && errno == EMSGSIZE) {
            ++worker->udp_stats.udp_drops_oversized;
            return;
        }
        if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            bpf2socks_udp_dns_close_channel(state, channel, bpf2socks_now_ms());
        }
        return;
    }
    bpf2socks_udp_downlink_release_reservation(state);

    for (int i = 0; i < received; ++i) {
        ++worker->udp_stats.udp_packets_from_upstream;
        if (bpf2socks_udp_relay_skip_unusable(worker, &messages[i])) continue;
        struct bpf2socks_dns_packet_info info;
        if (bpf2socks_dns_parse_response(messages[i].payload, messages[i].payload_len, &info) < 0) {
            ++worker->udp_stats.udp_drops_malformed_socks5;
            continue;
        }
        struct bpf2socks_dns_transaction *tx =
            bpf2socks_dns_table_find(&state->dns_table, channel->index, info.id);
        if (tx == NULL) continue;
        if (info.has_question && info.question_fingerprint != tx->question_fingerprint) continue;
        bpf2socks_dns_table_note_response(&state->dns_table, channel->index);
        ++worker->udp_stats.dns_valid_responses;

        bpf2socks_dns_set_id(messages[i].payload, messages[i].payload_len, tx->original_id);
        if (send_dns_response_to_client(state, worker, tx, &messages[i]) < 0) {
            ++worker->udp_stats.udp_send_errors;
            BPF2SOCKS_LOG_THROTTLED("failed to send DNS response to client: errno=%d", errno);
            bpf2socks_dns_table_release(&state->dns_table, tx);
            continue;
        }
        bpf2socks_dns_table_release(&state->dns_table, tx);
    }
}
