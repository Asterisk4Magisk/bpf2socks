// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/socks5.h"
#include "bridge/udp_internal.h"
#include "bridge/udp_relay_registry.h"
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

/* SOCKS5 UDP ASSOCIATE for client sessions and uplink sends to the relay. */

int bpf2socks_udp_associate_build_request(struct bpf2socks_udp_client_session *session) {
    if (session == NULL) {
        errno = EINVAL;
        return -1;
    }
    /* The method hello and the ASSOCIATE request go out together. */
    uint8_t *buf = session->associate_write_buf;
    size_t cap = sizeof(session->associate_write_buf);
    size_t hello_len = bpf2socks_socks5_build_hello(buf, cap);
    size_t request_len = bpf2socks_socks5_build_udp_associate_request(buf + hello_len, cap - hello_len);
    if (hello_len == 0U || request_len == 0U) {
        errno = EINVAL;
        return -1;
    }
    session->associate_write_len = hello_len + request_len;
    session->associate_write_offset = 0U;
    return 0;
}

int bpf2socks_udp_associate_open(
    const struct sockaddr *socks_addr,
    socklen_t socks_addr_len,
    enum bpf2socks_udp_session_stage *stage) {
    if (socks_addr == NULL || socks_addr_len == 0U || stage == NULL) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(socks_addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    bpf2socks_socket_tune_tcp_latency(fd, true);
    if (bpf2socks_socket_connect(fd, socks_addr, socks_addr_len) == 0) {
        *stage = BPF2SOCKS_UDP_SESSION_ASSOC_WRITE;
        return fd;
    }
    if (errno == EINPROGRESS) {
        *stage = BPF2SOCKS_UDP_SESSION_CONNECTING;
        return fd;
    }
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

static int finish_udp_associate_connect(struct bpf2socks_udp_client_session *session) {
    int error = 0;
    socklen_t error_len = sizeof(error);
    if (getsockopt(session->tcp_fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0) return -1;
    if (error != 0) {
        errno = error;
        return -1;
    }
    session->stage = BPF2SOCKS_UDP_SESSION_ASSOC_WRITE;
    return 0;
}

static int flush_udp_associate_write(struct bpf2socks_udp_client_session *session) {
    while (session->associate_write_offset < session->associate_write_len) {
        ssize_t sent = send(
            session->tcp_fd,
            session->associate_write_buf + session->associate_write_offset,
            session->associate_write_len - session->associate_write_offset,
            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (sent <= 0) return -1;
        session->associate_write_offset += (size_t)sent;
    }
    session->stage = BPF2SOCKS_UDP_SESSION_ASSOC_READ_HELLO;
    session->associate_read_len = 0U;
    session->associate_read_expected = 2U;
    return 1;
}

static int read_udp_associate_bytes(struct bpf2socks_udp_client_session *session) {
    while (session->associate_read_len < session->associate_read_expected) {
        ssize_t received = recv(
            session->tcp_fd,
            session->associate_read_buf + session->associate_read_len,
            session->associate_read_expected - session->associate_read_len,
            MSG_DONTWAIT);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (received <= 0) return -1;
        session->associate_read_len += (size_t)received;
        if (session->stage == BPF2SOCKS_UDP_SESSION_ASSOC_READ_RESPONSE) {
            size_t total = bpf2socks_socks5_reply_length(session->associate_read_buf, session->associate_read_len);
            if (total == SIZE_MAX || total > sizeof(session->associate_read_buf)) {
                errno = EPROTO;
                return -1;
            }
            if (total != 0U) {
                session->associate_read_expected = total;
            } else if (session->associate_read_len >= 4U) {
                session->associate_read_expected = 5U;
            }
        }
    }
    return 1;
}

static int read_udp_associate_hello(struct bpf2socks_udp_client_session *session) {
    int result = read_udp_associate_bytes(session);
    if (result <= 0) return result;
    if (session->associate_read_buf[0] != 0x05 || session->associate_read_buf[1] != 0x00) {
        errno = EPROTO;
        return -1;
    }
    session->stage = BPF2SOCKS_UDP_SESSION_ASSOC_READ_RESPONSE;
    session->associate_read_len = 0U;
    session->associate_read_expected = 4U;
    return 1;
}

/*
 * A connected relay socket caches the route and skips per-datagram
 * destination handling (including the cgroup UDP sendmsg hook). It also only
 * accepts datagrams from the relay, which is where SOCKS5 replies come from.
 * On failure the socket stays unconnected and sends name the relay.
 */
bool bpf2socks_udp_relay_connect(int udp_fd, const struct sockaddr_storage *relay_addr, socklen_t relay_addr_len) {
    return bpf2socks_socket_connect(udp_fd, (const struct sockaddr *)relay_addr, relay_addr_len) == 0;
}

const struct sockaddr *bpf2socks_udp_relay_destination(
    const struct sockaddr_storage *relay_addr,
    bool relay_connected) {
    return relay_connected ? NULL : (const struct sockaddr *)relay_addr;
}

static int create_udp_associate_relay_socket(
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session) {
    struct sockaddr_storage relay_addr;
    socklen_t relay_addr_len = 0U;
    size_t consumed = 0U;
    if (bpf2socks_socks5_parse_bound_addr(
            session->associate_read_buf,
            session->associate_read_len,
            &consumed,
            &relay_addr,
            &relay_addr_len) != 0 ||
        consumed != session->associate_read_len) {
        errno = EPROTO;
        return -1;
    }
    if (bpf2socks_socks5_replace_unspecified_relay(
            (const struct sockaddr *)&worker->socks_addr,
            &relay_addr,
            &relay_addr_len) < 0) {
        return -1;
    }
    int udp_fd = socket(relay_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (udp_fd < 0) return -1;
    bpf2socks_socket_tune_buffers(
        udp_fd,
        worker->config->udp_socket_buffer_size,
        worker->config->udp_socket_buffer_size);
    session->udp_fd = udp_fd;
    session->relay_addr = relay_addr;
    session->relay_addr_len = relay_addr_len;
    session->relay_connected = bpf2socks_udp_relay_connect(udp_fd, &relay_addr, relay_addr_len);
    return 0;
}

static bool udp_send_errno_is_transient(int error) {
    return error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS || error == ENOMEM;
}

/*
 * Sends datagrams to the session's SOCKS5 relay. A full send buffer drops the
 * datagrams it cannot take, as a congested link would, and keeps the session
 * with every reply binding alive. Returns how many were sent, or -1 when the
 * relay socket failed and the session must be dropped.
 */
int bpf2socks_udp_relay_send_batch(
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_msg *messages,
    unsigned int count) {
    unsigned int sent_total = 0U;
    unsigned int oversized = 0U;
    while (sent_total < count) {
        int sent = bpf2socks_socks5_udp_sendmmsg(
            session->udp_fd,
            bpf2socks_udp_relay_destination(&session->relay_addr, session->relay_connected),
            session->relay_addr_len,
            messages + sent_total,
            count - sent_total);
        if (sent > 0) {
            sent_total += (unsigned int)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        /* A datagram too large once the SOCKS5 header is added: drop it, not the session. */
        if (sent < 0 && errno == EMSGSIZE) {
            ++oversized;
            ++sent_total;
            continue;
        }
        if (sent < 0 && udp_send_errno_is_transient(errno)) {
            worker->udp_stats.udp_drops_send_busy += (uint64_t)(count - sent_total);
            break;
        }
        if (sent == 0) errno = EIO;
        return -1;
    }
    worker->udp_stats.udp_drops_oversized += (uint64_t)oversized;
    sent_total -= oversized;
    worker->udp_stats.udp_packets_to_upstream += (uint64_t)sent_total;
    worker->udp_stats.udp_copy_sends += (uint64_t)sent_total;
    return (int)sent_total;
}

static int flush_session_pending_packets(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session) {
    while (session->pending_head != NULL) {
        struct bpf2socks_udp_msg messages[BPF2SOCKS_UDP_MAX_BATCH];
        struct bpf2socks_udp_pending_packet *packets[BPF2SOCKS_UDP_MAX_BATCH];
        unsigned int count = 0U;
        for (struct bpf2socks_udp_pending_packet *packet = session->pending_head;
             packet != NULL && count < BPF2SOCKS_UDP_MAX_BATCH;
             packet = packet->next) {
            messages[count] = (struct bpf2socks_udp_msg){
                .addr = packet->original_dst,
                .payload = packet->payload,
                .payload_len = packet->payload_len,
            };
            packets[count] = packet;
            ++count;
        }
        if (bpf2socks_udp_relay_send_batch(worker, session, messages, count) < 0) return -1;
        session->last_seen_ms = bpf2socks_now_ms();
        bpf2socks_udp_lru_touch(state, session);
        /* Datagrams the relay socket could not take were counted and dropped. */
        for (unsigned int i = 0U; i < count; ++i) {
            struct bpf2socks_udp_pending_packet *packet = packets[i];
            if (session->pending_head == packet) session->pending_head = packet->next;
            if (session->pending_tail == packet) session->pending_tail = NULL;
            if (session->pending_count > 0U) --session->pending_count;
            bpf2socks_udp_session_release_pending(state, packet);
        }
    }
    session->pending_tail = NULL;
    return 0;
}

uint16_t bpf2socks_udp_sockaddr_port(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    return ntohs(((const struct sockaddr_in *)addr)->sin_port);
}

/*
 * Servers with one shared UDP relay (Mihomo answers every ASSOCIATE with its
 * own port) are not per-association and are never checked for collisions.
 */
bool bpf2socks_udp_relay_port_needs_claim(const struct bpf2socks_bridge_worker *worker, uint16_t relay_port) {
    return relay_port != 0U && relay_port != bpf2socks_udp_sockaddr_port(&worker->socks_addr);
}

/* Drops the association that came back on a taken relay port and asks again. */
static int restart_udp_associate(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session) {
    bpf2socks_udp_epoll_remove(state, session->tcp_fd);
    if (session->tcp_fd >= 0) close(session->tcp_fd);
    if (session->udp_fd >= 0) close(session->udp_fd);
    session->tcp_fd = -1;
    session->udp_fd = -1;
    memset(&session->relay_addr, 0, sizeof(session->relay_addr));
    session->relay_addr_len = 0U;
    session->relay_connected = false;
    if (bpf2socks_udp_associate_build_request(session) < 0) return -1;
    session->tcp_fd = bpf2socks_udp_associate_open(
        (const struct sockaddr *)&worker->socks_addr,
        worker->socks_addr_len,
        &session->stage);
    if (session->tcp_fd < 0) return -1;
    bpf2socks_udp_handshake_remove(state, session);
    bpf2socks_udp_handshake_add_tail(state, session, bpf2socks_now_ms());
    return bpf2socks_udp_epoll_add_session_control(state, session, EPOLLIN | EPOLLOUT);
}

static int complete_udp_associate(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session) {
    if (create_udp_associate_relay_socket(worker, session) < 0) return -1;
    uint16_t relay_port = bpf2socks_udp_sockaddr_port(&session->relay_addr);
    if (bpf2socks_udp_relay_port_needs_claim(worker, relay_port)) {
        if (bpf2socks_udp_relay_port_claim(worker->udp_relay_registry, relay_port)) {
            session->relay_port = relay_port;
            session->relay_port_claimed = true;
        } else {
            ++worker->udp_stats.udp_relay_port_collisions;
            if (session->associate_retries < BPF2SOCKS_UDP_RELAY_PORT_MAX_RETRIES) {
                ++session->associate_retries;
                return restart_udp_associate(state, worker, session);
            }
        }
    }
    if (bpf2socks_udp_epoll_switch_session_to_relay(state, session) < 0) return -1;
    session->stage = BPF2SOCKS_UDP_SESSION_READY;
    bpf2socks_udp_handshake_remove(state, session);
    ++worker->udp_stats.udp_associate_creates;
    return flush_session_pending_packets(state, worker, session);
}

int bpf2socks_udp_associate_advance(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    uint32_t events) {
    if ((events & (EPOLLERR | EPOLLHUP)) != 0) return -1;
    if (session->stage == BPF2SOCKS_UDP_SESSION_CONNECTING && (events & EPOLLOUT) != 0) {
        if (finish_udp_associate_connect(session) < 0) return -1;
    }
    if (session->stage == BPF2SOCKS_UDP_SESSION_ASSOC_WRITE && (events & EPOLLOUT) != 0) {
        int result = flush_udp_associate_write(session);
        if (result < 0) return -1;
        if (result > 0) {
            size_t index = bpf2socks_udp_session_index(state, session);
            if (index < state->session_cap) {
                struct bpf2socks_udp_fd_ref *ref = &state->session_refs[index].control;
                if (bpf2socks_udp_epoll_modify(state, session->tcp_fd, ref, EPOLLIN) < 0) return -1;
            }
        }
    }
    if (session->stage == BPF2SOCKS_UDP_SESSION_ASSOC_READ_HELLO && (events & EPOLLIN) != 0) {
        int result = read_udp_associate_hello(session);
        if (result < 0) return -1;
        if (result == 0) return 0;
    }
    if (session->stage == BPF2SOCKS_UDP_SESSION_ASSOC_READ_RESPONSE && (events & EPOLLIN) != 0) {
        int result = read_udp_associate_bytes(session);
        if (result < 0) return -1;
        if (result > 0) return complete_udp_associate(state, worker, session);
    }
    return 0;
}
