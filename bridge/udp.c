// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf2socks.h"
#include "bridge/dns.h"
#include "bridge/internal.h"
#include "bridge/socks5.h"
#include "bridge/udp_binding_index.h"
#include "bridge/udp_budget.h"
#include "bridge/udp_destroy_events.h"
#include "bridge/udp_downlink_queue.h"
#include "bridge/udp_internal.h"
#include "core/log.h"
#include "core/stop_event.h"
#include "core/token.h"
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

/* UDP worker: event loop, client and relay datagram ingress, maintenance. */

static void publish_udp_stats_if_due(
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms,
    uint64_t *next_publish_ms,
    bool force) {
    if (worker == NULL || worker->config == NULL || !worker->config->debug_stats || next_publish_ms == NULL) {
        return;
    }
    if (!force && (now_ms == 0U || (*next_publish_ms != 0U && now_ms < *next_publish_ms))) {
        return;
    }
    bpf2socks_bridge_publish_udp_stats(worker);
    if (now_ms != 0U) *next_publish_ms = now_ms + BPF2SOCKS_UDP_STATS_PUBLISH_MILLISECONDS;
}

/* Counts a relay datagram that recvmmsg could not decode; true means skip it. */
bool bpf2socks_udp_relay_skip_unusable(
    struct bpf2socks_bridge_worker *worker,
    const struct bpf2socks_udp_msg *message) {
    if (message->error == 0) return false;
    if (message->error == EMSGSIZE) {
        ++worker->udp_stats.udp_drops_oversized;
    } else {
        ++worker->udp_stats.udp_drops_malformed_socks5;
    }
    return true;
}

static void handle_udp_client_packets(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    int listener_fd,
    uint8_t *client_payloads) {
    uint32_t batch = state->batch_size;
    size_t payload_stride = BPF2SOCKS_UDP_BUFFER_SIZE;

    struct mmsghdr vec[batch];
    struct iovec iov[batch];
    struct sockaddr_storage addrs[batch];
    char control[batch][CMSG_SPACE(sizeof(struct in_pktinfo)) +
                        CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                        CMSG_SPACE(sizeof(struct sockaddr_in)) +
                        CMSG_SPACE(sizeof(struct sockaddr_in6))];
    /* Every field the kernel reads is set below; addresses and cmsgs are outputs. */
    for (uint32_t i = 0; i < batch; ++i) {
        iov[i].iov_base = client_payloads + (size_t)i * payload_stride;
        iov[i].iov_len = payload_stride;
        vec[i].msg_hdr.msg_name = &addrs[i];
        vec[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
        vec[i].msg_hdr.msg_iov = &iov[i];
        vec[i].msg_hdr.msg_iovlen = 1;
        vec[i].msg_hdr.msg_control = control[i];
        vec[i].msg_hdr.msg_controllen = sizeof(control[i]);
        vec[i].msg_hdr.msg_flags = 0;
        vec[i].msg_len = 0U;
    }

    int received = recvmmsg(listener_fd, vec, batch, MSG_DONTWAIT, NULL);
    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            BPF2SOCKS_LOG_THROTTLED("failed to receive UDP client packet batch: errno=%d", errno);
        }
        return;
    }

    struct bpf2socks_udp_client_session *outgoing_sessions[batch];
    struct bpf2socks_udp_msg outgoing_messages[batch];
    unsigned int outgoing_count = 0U;
    struct bpf2socks_dns_transaction *dns_transactions[batch];
    uint32_t dns_channel_indices[batch];
    struct bpf2socks_udp_msg dns_messages[batch];
    unsigned int dns_count = 0U;
    /* Only the first outgoing_count/dns_count entries are ever read. */
    uint64_t now_ms = bpf2socks_now_ms();
    bpf2socks_udp_dns_expire_transactions(state, worker, now_ms);

    for (int i = 0; i < received; ++i) {
        struct bpf2socks_udp_client_packet packet;
        memset(&packet, 0, sizeof(packet));
        if ((vec[i].msg_hdr.msg_flags & MSG_TRUNC) != 0 || vec[i].msg_len > payload_stride) {
            ++worker->udp_stats.udp_drops_oversized;
            BPF2SOCKS_LOG_THROTTLED("dropping truncated UDP client packet: len=%u flags=0x%x",
                vec[i].msg_len,
                vec[i].msg_hdr.msg_flags);
            continue;
        }
        packet.client_addr = addrs[i];
        packet.client_addr_len = vec[i].msg_hdr.msg_namelen;
        packet.payload = client_payloads + (size_t)i * payload_stride;
        packet.payload_len = vec[i].msg_len;
        ++worker->udp_stats.udp_packets_from_client;

        struct bpf2socks_udp_client_session *existing_session = NULL;
        int parse_result = bpf2socks_udp_token_parse_cmsgs(&vec[i].msg_hdr, worker->config, &packet);
        if (parse_result == 0) {
            existing_session = bpf2socks_udp_session_find(state, &packet.client_addr, packet.client_addr_len);
        }
        enum bpf2socks_token_lookup_mode preference = existing_session != NULL
            ? existing_session->token_lookup_mode
            : BPF2SOCKS_TOKEN_LOOKUP_UNKNOWN;
        if (parse_result < 0 ||
            (bpf2socks_udp_token_lookup_original(state, worker, &packet, preference, now_ms) < 0 &&
             bpf2socks_udp_token_recover_connected(worker, existing_session, &packet) < 0)) {
            ++worker->udp_stats.udp_token_misses;
            BPF2SOCKS_LOG_THROTTLED("missing UDP original destination: errno=%d", errno);
            if (parse_result == 0) bpf2socks_udp_token_notify_unknown(state, worker->config, &packet, now_ms);
            continue;
        }
        if (existing_session != NULL && packet.token_lookup_mode != BPF2SOCKS_TOKEN_LOOKUP_UNKNOWN) {
            existing_session->token_lookup_mode = packet.token_lookup_mode;
        }

        if (bpf2socks_udp_dns_is_candidate(worker->config, &packet)) {
            struct bpf2socks_dns_packet_info dns_info;
            if (bpf2socks_dns_parse_query(packet.payload, packet.payload_len, &dns_info) == 0) {
                if (bpf2socks_udp_dns_prepare_query(
                        state,
                        worker,
                        &packet,
                        &dns_info,
                        now_ms,
                        &dns_transactions[dns_count],
                        &dns_channel_indices[dns_count],
                        &dns_messages[dns_count]) == 0) {
                    ++dns_count;
                    continue;
                }
                // DNS channel not ready (handshaking); fall through to
                // regular UDP session path instead of dropping the query.
            }
        }

        struct bpf2socks_udp_client_session *session = bpf2socks_udp_session_get(state, &packet, worker, existing_session);
        if (session == NULL) {
            BPF2SOCKS_LOG_THROTTLED("SOCKS5 UDP ASSOCIATE failed: errno=%d", errno);
            continue;
        }
        struct bpf2socks_udp_reply_binding *binding = bpf2socks_udp_binding_find(
            state, session, &packet.original_dst, worker);
        if (binding == NULL) {
            binding = bpf2socks_udp_binding_create_for_packet(state, session, &packet, worker);
            if (binding == NULL) continue;
        } else {
            ++worker->udp_stats.udp_reply_binding_hits;
            memcpy(binding->token_addr, packet.token_addr, packet.token_family == AF_INET6 ? 16U : 4U);
            bool needs_original_reply_socket =
                !bpf2socks_udp_packet_uses_connected_token(&packet) &&
                (packet.original_from_socket || bpf2socks_udp_packet_needs_original_reply_socket(&packet));
            if (!needs_original_reply_socket && binding->reply_fd >= 0) {
                bpf2socks_udp_binding_close_reply(binding);
            } else if (needs_original_reply_socket && binding->reply_fd < 0) {
                bool reply_raw = false;
                int reply_fd = bpf2socks_udp_reply_socket_create(&binding->original_dst, &reply_raw);
                if (reply_fd < 0) {
                    BPF2SOCKS_LOG_THROTTLED("failed to create UDP original reply socket: errno=%d", errno);
                    continue;
                }
                bpf2socks_udp_binding_set_reply(binding, reply_fd, reply_raw);
            }
            binding->connected_udp_token = packet.connected_udp_token;
            binding->last_seen_ms = now_ms;
            bpf2socks_udp_binding_lru_touch(state, session, binding);
        }

        if (session->stage != BPF2SOCKS_UDP_SESSION_READY) {
            if (bpf2socks_udp_session_queue_pending(
                    state,
                    session,
                    &packet.original_dst,
                    packet.payload,
                    packet.payload_len,
                    payload_stride) < 0) {
                if (errno == ENOBUFS) {
                    ++worker->udp_stats.udp_drops_pending_budget;
                    BPF2SOCKS_LOG_THROTTLED("dropping UDP pending packet: pending budget exhausted");
                } else {
                    ++worker->udp_stats.udp_send_errors;
                }
            }
            continue;
        }

        outgoing_sessions[outgoing_count] = session;
        outgoing_messages[outgoing_count] = (struct bpf2socks_udp_msg){
            .addr = packet.original_dst,
            .payload = packet.payload,
            .payload_len = packet.payload_len,
        };
        ++outgoing_count;
    }

    bpf2socks_udp_dns_flush_outgoing(state, worker, dns_transactions, dns_channel_indices, dns_messages, dns_count);

    for (unsigned int i = 0U; i < outgoing_count; ++i) {
        struct bpf2socks_udp_client_session *session = outgoing_sessions[i];
        if (session == NULL) continue;
        struct bpf2socks_udp_send_batch send_batch;
        memset(&send_batch, 0, sizeof(send_batch));
        send_batch.session = session;
        for (unsigned int j = i; j < outgoing_count; ++j) {
            if (outgoing_sessions[j] != session) continue;
            send_batch.messages[send_batch.count++] = outgoing_messages[j];
            outgoing_sessions[j] = NULL;
        }
        if (bpf2socks_udp_relay_send_batch(worker, session, send_batch.messages, send_batch.count) < 0) {
            ++worker->udp_stats.udp_send_errors;
            BPF2SOCKS_LOG_THROTTLED("SOCKS5 UDP send failed: errno=%d", errno);
            bpf2socks_udp_session_drop(state, session);
        }
    }
}

static void handle_udp_upstream_packets(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    uint8_t *upstream_packets) {
    uint32_t batch = state->batch_size;
    if (bpf2socks_udp_downlink_reserve_slots(state, &batch) < 0) {
        bpf2socks_udp_downlink_waiter_tracker_mark_waiting(
            &state->downlink_budget_waiters,
            &session->downlink_waiting_budget);
        if (bpf2socks_udp_downlink_set_paused(state, session, true) < 0) {
            ++worker->udp_stats.udp_send_errors;
            bpf2socks_udp_session_drop(state, session);
        }
        return;
    }
    size_t stride = BPF2SOCKS_UDP_BUFFER_SIZE + BPF2SOCKS_MAX_SOCKS5_UDP_HEADER;

    struct bpf2socks_udp_msg messages[batch];
    int received = bpf2socks_socks5_udp_recvmmsg(session->udp_fd, messages, batch, upstream_packets, stride);
    if (received <= 0) {
        int receive_errno = errno;
        bpf2socks_udp_downlink_release_reservation(state);
        errno = receive_errno;
        if (received < 0 && errno == EMSGSIZE) {
            ++worker->udp_stats.udp_drops_oversized;
            return;
        }
        if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) bpf2socks_udp_session_drop(state, session);
        return;
    }

    struct bpf2socks_udp_downlink_batch downlink_batch;
    bpf2socks_udp_downlink_batch_init(&downlink_batch);
    bool drop_session_after_reservation = false;

    for (int i = 0; i < received; ++i) {
        ++worker->udp_stats.udp_packets_from_upstream;
        if (bpf2socks_udp_relay_skip_unusable(worker, &messages[i])) continue;
        if (messages[i].addr.family == AF_UNSPEC) {
            struct bpf2socks_udp_reply_binding *domain_binding =
                bpf2socks_udp_binding_find_by_domain_port(session, messages[i].addr.port);
            if (domain_binding == NULL) {
                ++worker->udp_stats.udp_drops_malformed_socks5;
                continue;
            }
            messages[i].addr = domain_binding->original_dst;
        }
        struct bpf2socks_udp_reply_binding *binding = bpf2socks_udp_binding_find(
            state, session, &messages[i].addr, worker);
        if (binding == NULL) {
            binding = bpf2socks_udp_binding_create_fullcone(state, session, &messages[i].addr, worker);
            if (binding == NULL) {
                ++worker->udp_stats.udp_drops_malformed_socks5;
                continue;
            }
        } else {
            ++worker->udp_stats.udp_reply_binding_hits;
            bpf2socks_udp_binding_lru_touch(state, session, binding);
        }
        if (binding->reply_fd >= 0) {
            if (binding->reply_raw) {
                if (bpf2socks_udp_downlink_batch_flush(state, &downlink_batch, worker) < 0) {
                    ++worker->udp_stats.udp_send_errors;
                    BPF2SOCKS_LOG_THROTTLED("failed to send UDP response batch to client: errno=%d", errno);
                    drop_session_after_reservation = true;
                    goto done;
                }
                if (bpf2socks_udp_downlink_find_channel(session, binding, binding->reply_fd, false, true) != NULL) {
                    if (bpf2socks_udp_downlink_queue_packet(
                            state,
                            session,
                            binding,
                            &messages[i],
                            binding->reply_fd,
                            false,
                            true) < 0) {
                        ++worker->udp_stats.udp_send_errors;
                        BPF2SOCKS_LOG_THROTTLED("failed to queue UDP raw response to client: errno=%d", errno);
                        drop_session_after_reservation = true;
                        goto done;
                    }
                    continue;
                }
                int send_result = binding->original_dst.family == AF_INET6
                    ? bpf2socks_udp_raw_send6(
                          binding->reply_fd,
                          session,
                          binding,
                          messages[i].payload,
                          messages[i].payload_len)
                    : bpf2socks_udp_raw_send4(
                          binding->reply_fd,
                          session,
                          binding,
                          messages[i].payload,
                          messages[i].payload_len);
                if (send_result < 0) {
                    int send_errno = errno;
                    /* A header-included raw send is never fragmented: drop only
                     * the datagram larger than the route MTU, not the session. */
                    if (send_errno == EMSGSIZE) {
                        ++worker->udp_stats.udp_drops_oversized;
                        BPF2SOCKS_LOG_THROTTLED("dropping UDP response larger than the client route MTU: len=%zu",
                            messages[i].payload_len);
                        continue;
                    }
                    if (bpf2socks_udp_downlink_classify_send_result(-1, 1U, send_errno) ==
                        BPF2SOCKS_UDP_DOWNLINK_SEND_RETRY) {
                        if (bpf2socks_udp_downlink_queue_packet(
                                state,
                                session,
                                binding,
                                &messages[i],
                                binding->reply_fd,
                                false,
                                true) == 0) {
                            continue;
                        }
                    }
                    ++worker->udp_stats.udp_send_errors;
                    BPF2SOCKS_LOG_THROTTLED("failed to send UDP response to client: errno=%d", errno);
                    drop_session_after_reservation = true;
                    goto done;
                }
                uint64_t now_ms = bpf2socks_now_ms();
                session->last_seen_ms = now_ms;
                binding->last_seen_ms = now_ms;
                bpf2socks_udp_lru_touch(state, session);
                ++worker->udp_stats.udp_packets_to_client;
                ++worker->udp_stats.udp_copy_sends;
            } else {
                if (bpf2socks_udp_downlink_batch_queue(
                        state,
                        &downlink_batch,
                        worker,
                        session,
                        binding,
                        &messages[i],
                        binding->reply_fd,
                        false) < 0) {
                    ++worker->udp_stats.udp_send_errors;
                    BPF2SOCKS_LOG_THROTTLED("failed to send UDP response batch to client: errno=%d", errno);
                    drop_session_after_reservation = true;
                    goto done;
                }
            }
        } else {
            int reply_listener_fd = session->client_addr.ss_family == AF_INET6 && worker->udp6_listener_fd >= 0
                ? worker->udp6_listener_fd
                : worker->udp4_listener_fd;
            if (bpf2socks_udp_downlink_batch_queue(
                    state,
                    &downlink_batch,
                    worker,
                    session,
                    binding,
                    &messages[i],
                    reply_listener_fd,
                    true) < 0) {
                ++worker->udp_stats.udp_send_errors;
                BPF2SOCKS_LOG_THROTTLED("failed to send UDP response batch to client: errno=%d", errno);
                drop_session_after_reservation = true;
                goto done;
            }
        }
    }

    if (bpf2socks_udp_downlink_batch_flush(state, &downlink_batch, worker) < 0) {
        ++worker->udp_stats.udp_send_errors;
        BPF2SOCKS_LOG_THROTTLED("failed to send UDP response batch to client: errno=%d", errno);
        drop_session_after_reservation = true;
    }

done:
    bpf2socks_udp_downlink_release_reservation(state);
    if (drop_session_after_reservation) {
        bpf2socks_udp_session_drop(state, session);
    }
}

static int init_state(struct bpf2socks_udp_state *state, struct bpf2socks_bridge_worker *worker) {
    if (state == NULL || worker == NULL || worker->config == NULL || worker->udp_pending_budget == NULL ||
        worker->udp_session_cap == 0U || worker->udp_binding_cap == 0U ||
        worker->udp_pending_budget->cap_bytes < bpf2socks_udp_downlink_max_allocation()) {
        errno = EINVAL;
        return -1;
    }
    memset(state, 0, sizeof(*state));
    state->epoll_fd = -1;
    state->dns_raw4_fd = -1;
    state->dns_raw6_fd = -1;
    state->token_notice4_fd = -1;
    state->token_notice6_fd = -1;
    state->budget_wake_fd = -1;
    state->next_deadline_ms = BPF2SOCKS_NO_DEADLINE;
    state->relay_registry = worker->udp_relay_registry;
    state->destroy_events_fd = -1;
    state->release_retry_due_ms = BPF2SOCKS_NO_DEADLINE;
    state->batch_size = worker->config->udp_batch_size < BPF2SOCKS_UDP_MAX_BATCH
        ? worker->config->udp_batch_size
        : BPF2SOCKS_UDP_MAX_BATCH;
    state->idle_timeout_ms = (uint64_t)worker->config->udp_idle_timeout_milliseconds;
    state->released_ports = calloc(1U, BPF2SOCKS_UDP_PORT_BITMAP_BYTES);
    state->port_destroyed_ms = calloc(65536U, sizeof(*state->port_destroyed_ms));
    size_t max_sessions = worker->udp_session_cap;
    state->binding_cap = worker->udp_binding_cap;
    state->pending_budget = worker->udp_pending_budget;
    bpf2socks_udp_downlink_waiter_tracker_init(&state->downlink_budget_waiters);
    state->sessions = calloc(max_sessions, sizeof(*state->sessions));
    state->bindings = calloc(state->binding_cap, sizeof(*state->bindings));
    state->session_refs = calloc(max_sessions, sizeof(*state->session_refs));
    state->event_cap = max_sessions * 3U + state->binding_cap + 2U +
        BPF2SOCKS_DNS_CHANNELS_PER_WORKER * 2U;
    state->events = calloc(state->event_cap, sizeof(*state->events));
    state->session_buckets = calloc(BPF2SOCKS_SESSION_HASH_BUCKETS, sizeof(*state->session_buckets));
    if (state->sessions == NULL || state->bindings == NULL || state->session_refs == NULL ||
        state->events == NULL || state->session_buckets == NULL) {
        free(state->sessions);
        free(state->bindings);
        free(state->session_refs);
        free(state->events);
        free(state->session_buckets);
        memset(state, 0, sizeof(*state));
        return -1;
    }
    if (bpf2socks_udp_binding_index_init(&state->binding_index, state->binding_cap) != 0) {
        free(state->session_buckets);
        free(state->events);
        free(state->session_refs);
        free(state->bindings);
        free(state->sessions);
        memset(state, 0, sizeof(*state));
        state->epoll_fd = -1;
        return -1;
    }
    state->session_cap = max_sessions;
    for (size_t i = 0; i < max_sessions; ++i) {
        state->sessions[i].tcp_fd = -1;
        state->sessions[i].udp_fd = -1;
        state->sessions[i].free_next = state->free_sessions;
        state->free_sessions = &state->sessions[i];
        state->session_refs[i].control.kind = BPF2SOCKS_UDP_FD_SESSION_CONTROL;
        state->session_refs[i].control.fd = -1;
        state->session_refs[i].relay.kind = BPF2SOCKS_UDP_FD_SESSION_RELAY;
        state->session_refs[i].relay.fd = -1;
    }
    for (size_t i = 0; i < state->binding_cap; ++i) {
        state->bindings[i].reply_fd = -1;
        state->bindings[i].free_next = state->free_bindings;
        state->free_bindings = &state->bindings[i];
    }
    state->listener4_ref.kind = BPF2SOCKS_UDP_FD_LISTENER4;
    state->listener4_ref.fd = -1;
    state->listener6_ref.kind = BPF2SOCKS_UDP_FD_LISTENER6;
    state->listener6_ref.fd = -1;
    for (uint32_t i = 0U; i < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++i) {
        state->dns_channels[i].index = i;
        state->dns_channels[i].tcp_fd = -1;
        state->dns_channels[i].udp_fd = -1;
        state->dns_channels[i].control_ref.kind = BPF2SOCKS_UDP_FD_DNS_CONTROL;
        state->dns_channels[i].control_ref.fd = -1;
        state->dns_channels[i].control_ref.dns_channel_index = i;
        state->dns_channels[i].relay_ref.kind = BPF2SOCKS_UDP_FD_DNS_RELAY;
        state->dns_channels[i].relay_ref.fd = -1;
        state->dns_channels[i].relay_ref.dns_channel_index = i;
    }
    if (bpf2socks_dns_table_init(
            &state->dns_table,
            BPF2SOCKS_DNS_CHANNELS_PER_WORKER,
            BPF2SOCKS_DNS_MAX_TRANSACTIONS_PER_WORKER) < 0) {
        bpf2socks_udp_binding_index_free(&state->binding_index);
        free(state->session_buckets);
        free(state->events);
        free(state->session_refs);
        free(state->bindings);
        free(state->sessions);
        memset(state, 0, sizeof(*state));
        state->epoll_fd = -1;
        return -1;
    }
    return 0;
}

static void free_state(struct bpf2socks_udp_state *state) {
    if (state == NULL) return;
    for (uint32_t i = 0U; i < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++i) {
        bpf2socks_udp_dns_close_channel(state, &state->dns_channels[i], bpf2socks_now_ms());
    }
    if (state->dns_raw4_fd >= 0) {
        close(state->dns_raw4_fd);
        state->dns_raw4_fd = -1;
    }
    if (state->dns_raw6_fd >= 0) {
        close(state->dns_raw6_fd);
        state->dns_raw6_fd = -1;
    }
    if (state->token_notice4_fd >= 0) {
        close(state->token_notice4_fd);
        state->token_notice4_fd = -1;
    }
    if (state->token_notice6_fd >= 0) {
        close(state->token_notice6_fd);
        state->token_notice6_fd = -1;
    }
    if (state->destroy_events_fd >= 0) {
        close(state->destroy_events_fd);
        state->destroy_events_fd = -1;
    }
    if (state->budget_wake_fd >= 0) {
        bpf2socks_udp_budget_set_wake_fd(state->pending_budget, state->worker_id, -1);
        close(state->budget_wake_fd);
        state->budget_wake_fd = -1;
    }
    if (state->epoll_fd >= 0) {
        close(state->epoll_fd);
        state->epoll_fd = -1;
    }
    for (size_t i = 0; i < state->session_cap; ++i) {
        bpf2socks_udp_session_close(state, &state->sessions[i]);
    }
    bpf2socks_udp_downlink_free_retired(state);
    free(state->session_buckets);
    free(state->events);
    free(state->session_refs);
    bpf2socks_udp_binding_index_free(&state->binding_index);
    free(state->bindings);
    free(state->sessions);
    bpf2socks_dns_table_free(&state->dns_table);
    free(state->token_cache);
    free(state->released_ports);
    free(state->port_destroyed_ms);
    memset(state, 0, sizeof(*state));
}

/*
 * Mirrors the expiry walks: each list is ordered oldest first, and an expired
 * entry that is still draining downlink packets is skipped because its
 * progress is driven by socket events, not by time.
 */
static uint64_t udp_next_deadline(
    const struct bpf2socks_udp_state *state,
    const struct bpf2socks_runtime_config *config,
    uint64_t now_ms) {
    uint64_t next = BPF2SOCKS_NO_DEADLINE;
    uint64_t idle_ms = state->idle_timeout_ms;
    for (const struct bpf2socks_udp_client_session *session = state->lru_head;
         session != NULL && session->used;
         session = session->lru_next) {
        uint64_t deadline = session->last_seen_ms + idle_ms;
        bool draining = session->downlink_pending_count > 0U || session->downlink_waiting_budget;
        if (deadline > now_ms || !draining) {
            bpf2socks_deadline_note(&next, deadline);
            break;
        }
    }
    bpf2socks_deadline_note(&next, state->release_retry_due_ms);
    for (const struct bpf2socks_udp_reply_binding *binding = state->binding_lru_head;
         binding != NULL && binding->used;
         binding = binding->global_lru_next) {
        uint64_t deadline = binding->last_seen_ms + idle_ms;
        if (deadline > now_ms || binding->downlink_pending_count == 0U) {
            bpf2socks_deadline_note(&next, deadline);
            break;
        }
    }
    uint64_t dns_sent_at_ms = 0U;
    if (bpf2socks_dns_table_oldest(&state->dns_table, &dns_sent_at_ms)) {
        bpf2socks_deadline_note(&next, dns_sent_at_ms + config->dns_transaction_timeout_milliseconds);
    }
    for (uint32_t i = 0U; i < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++i) {
        const struct bpf2socks_udp_dns_channel *channel = &state->dns_channels[i];
        if (channel->stage == BPF2SOCKS_UDP_DNS_IDLE || channel->stage == BPF2SOCKS_UDP_DNS_READY ||
            channel->stage_started_ms == 0U) {
            continue;
        }
        bpf2socks_deadline_note(&next,
            channel->stage_started_ms + BPF2SOCKS_DNS_HANDSHAKE_TIMEOUT_MILLISECONDS);
    }
    if (state->handshake_head != NULL) {
        bpf2socks_deadline_note(&next,
            state->handshake_head->handshake_started_ms + config->connect_timeout_milliseconds);
    }
    return next;
}

static bool udp_has_budget_waiters(const struct bpf2socks_udp_state *state) {
    if (bpf2socks_udp_downlink_waiter_tracker_has_waiters(&state->downlink_budget_waiters)) return true;
    for (uint32_t i = 0U; i < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++i) {
        if (state->dns_channels[i].relay_paused) return true;
    }
    return false;
}

static void udp_run_maintenance(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t *next_stats_publish_ms) {
    bpf2socks_udp_downlink_free_retired(state);
    bpf2socks_udp_downlink_resume_budget_waiters(state);
    bpf2socks_udp_binding_expire_idle(state, worker);
    bpf2socks_udp_session_expire_handshakes(state, worker, bpf2socks_now_ms());
    bpf2socks_udp_session_expire_idle(state);
    bpf2socks_udp_release_retry(state, worker, bpf2socks_now_ms());
    bpf2socks_udp_dns_expire_transactions(state, worker, bpf2socks_now_ms());
    bpf2socks_udp_dns_expire_handshakes(state, bpf2socks_now_ms());
    bpf2socks_udp_downlink_free_retired(state);
    if (udp_has_budget_waiters(state)) {
        /* Register first, then re-check, so a release in between still wakes us. */
        bpf2socks_udp_budget_wait(state->pending_budget, state->worker_id);
        bpf2socks_udp_downlink_resume_budget_waiters(state);
    }
    publish_udp_stats_if_due(worker, bpf2socks_now_ms(), next_stats_publish_ms, false);
    bpf2socks_udp_release_disarm_if_idle(state);
    state->next_deadline_ms = udp_next_deadline(state, worker->config, bpf2socks_now_ms());
}

int bpf2socks_bridge_udp_run(struct bpf2socks_bridge_worker *worker) {
    if (worker == NULL || worker->udp4_listener_fd < 0 || worker->config == NULL) return -1;
    struct bpf2socks_udp_state state;
    if (init_state(&state, worker) < 0) return -1;

    uint32_t batch = state.batch_size;
    size_t payload_stride = BPF2SOCKS_UDP_BUFFER_SIZE;
    size_t upstream_stride = payload_stride + BPF2SOCKS_MAX_SOCKS5_UDP_HEADER;

    uint8_t *client_payloads = calloc(batch, payload_stride);
    uint8_t *upstream_packets = calloc(batch, upstream_stride);
    if (client_payloads == NULL || upstream_packets == NULL) {
        free(client_payloads);
        free(upstream_packets);
        free_state(&state);
        return -1;
    }

    state.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (state.epoll_fd < 0) {
        free(client_payloads);
        free(upstream_packets);
        free_state(&state);
        return -1;
    }
    struct epoll_event stop_event;
    memset(&stop_event, 0, sizeof(stop_event));
    stop_event.events = EPOLLIN;
    int stop_fd = bpf2socks_stop_event_fd();
    if (stop_fd < 0 || epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, stop_fd, &stop_event) != 0) {
        int saved = stop_fd < 0 ? EINVAL : errno;
        free(client_payloads);
        free(upstream_packets);
        free_state(&state);
        errno = saved;
        return -1;
    }
    state.worker_id = worker->id;
    state.budget_wake_fd = eventfd(0U, EFD_NONBLOCK | EFD_CLOEXEC);
    state.budget_wake_ref.kind = BPF2SOCKS_UDP_FD_BUDGET_WAKE;
    state.budget_wake_ref.fd = state.budget_wake_fd;
    if (state.budget_wake_fd < 0 ||
        bpf2socks_udp_epoll_add(&state, state.budget_wake_fd, &state.budget_wake_ref) < 0) {
        free(client_payloads);
        free(upstream_packets);
        free_state(&state);
        return -1;
    }
    bpf2socks_udp_budget_set_wake_fd(state.pending_budget, state.worker_id, state.budget_wake_fd);
    state.destroy_events_fd = bpf2socks_udp_destroy_events_open();
    state.destroy_events_ref.kind = BPF2SOCKS_UDP_FD_DESTROY_EVENTS;
    state.destroy_events_ref.fd = state.destroy_events_fd;
    if (state.released_ports == NULL || state.port_destroyed_ms == NULL || state.destroy_events_fd < 0 ||
        bpf2socks_udp_epoll_add(&state, state.destroy_events_fd, &state.destroy_events_ref) < 0) {
        int saved = (state.released_ports == NULL || state.port_destroyed_ms == NULL) ? ENOMEM : errno;
        bpf2socks_log("UDP socket destroy notifications are unavailable: errno=%d", saved);
        free(client_payloads);
        free(upstream_packets);
        free_state(&state);
        errno = saved;
        return -1;
    }
    state.destroy_events_armed = true;
    state.listener4_ref.fd = worker->udp4_listener_fd;
    if (bpf2socks_udp_epoll_add(&state, worker->udp4_listener_fd, &state.listener4_ref) < 0) {
        free(client_payloads);
        free(upstream_packets);
        free_state(&state);
        return -1;
    }
    if (worker->udp6_listener_fd >= 0) {
        state.listener6_ref.fd = worker->udp6_listener_fd;
        if (bpf2socks_udp_epoll_add(&state, worker->udp6_listener_fd, &state.listener6_ref) < 0) {
            free(client_payloads);
            free(upstream_packets);
            free_state(&state);
            return -1;
        }
    }

    int result = 0;
    int wait_errno = 0;
    uint64_t next_stats_publish_ms = 0U;
    while (!bpf2socks_stop_requested()) {
        int timeout = bpf2socks_deadline_udp_wait_timeout(
            state.next_deadline_ms,
            bpf2socks_now_ms(),
            worker->config->debug_stats);
        int ready = epoll_wait(state.epoll_fd, state.events, (int)state.event_cap, timeout);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            wait_errno = errno;
            result = -1;
            break;
        }
        if (bpf2socks_stop_requested()) break;
        if (ready == 0) {
            udp_run_maintenance(&state, worker, &next_stats_publish_ms);
            continue;
        }
        for (int i = 0; i < ready; ++i) {
            struct bpf2socks_udp_fd_ref *ref = state.events[i].data.ptr;
            if (ref == NULL) continue;
            uint32_t events = state.events[i].events;
            if (ref->kind == BPF2SOCKS_UDP_FD_BUDGET_WAKE) {
                uint64_t wakeups = 0U;
                (void)read(state.budget_wake_fd, &wakeups, sizeof(wakeups));
                continue;
            }
            if (ref->kind == BPF2SOCKS_UDP_FD_DESTROY_EVENTS) {
                bpf2socks_udp_release_handle_events(&state, worker, bpf2socks_now_ms());
                continue;
            }
            if ((events & EPOLLIN) != 0 && ref->kind == BPF2SOCKS_UDP_FD_LISTENER4) {
                handle_udp_client_packets(&state, worker, worker->udp4_listener_fd, client_payloads);
            } else if ((events & EPOLLIN) != 0 && ref->kind == BPF2SOCKS_UDP_FD_LISTENER6) {
                handle_udp_client_packets(&state, worker, worker->udp6_listener_fd, client_payloads);
            } else if (ref->kind == BPF2SOCKS_UDP_FD_SESSION_CONTROL &&
                ref->session != NULL &&
                ref->session->used) {
                if (ref->session->stage != BPF2SOCKS_UDP_SESSION_READY) {
                    if (bpf2socks_udp_associate_advance(&state, worker, ref->session, events) < 0) {
                        ++worker->udp_stats.udp_send_errors;
                        bpf2socks_udp_session_drop(&state, ref->session);
                    }
                } else {
                    bpf2socks_udp_session_control_event(&state, ref->session, events);
                }
            } else if (ref->kind == BPF2SOCKS_UDP_FD_SESSION_RELAY &&
                ref->session != NULL &&
                ref->session->used &&
                ref->session->stage == BPF2SOCKS_UDP_SESSION_READY) {
                if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
                    bpf2socks_udp_session_drop(&state, ref->session);
                } else if ((events & EPOLLIN) != 0) {
                    handle_udp_upstream_packets(&state, worker, ref->session, upstream_packets);
                }
            } else if (ref->kind == BPF2SOCKS_UDP_FD_DOWNLINK &&
                ref->downlink != NULL &&
                ref->session != NULL &&
                ref->session->used) {
                if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
                    ++worker->udp_stats.udp_send_errors;
                    bpf2socks_udp_session_drop(&state, ref->session);
                } else if ((events & EPOLLOUT) != 0 &&
                    bpf2socks_udp_downlink_flush_channel(&state, worker, ref->downlink) < 0) {
                    ++worker->udp_stats.udp_send_errors;
                    BPF2SOCKS_LOG_THROTTLED("failed to retry UDP response to client: errno=%d", errno);
                    bpf2socks_udp_session_drop(&state, ref->session);
                }
            } else if (ref->kind == BPF2SOCKS_UDP_FD_DNS_CONTROL &&
                ref->dns_channel_index < BPF2SOCKS_DNS_CHANNELS_PER_WORKER) {
               struct bpf2socks_udp_dns_channel *channel = &state.dns_channels[ref->dns_channel_index];
                bpf2socks_udp_dns_control_event(&state, worker, channel, events, bpf2socks_now_ms());
            } else if (ref->kind == BPF2SOCKS_UDP_FD_DNS_RELAY &&
                ref->dns_channel_index < BPF2SOCKS_DNS_CHANNELS_PER_WORKER) {
                struct bpf2socks_udp_dns_channel *channel = &state.dns_channels[ref->dns_channel_index];
                if (!channel->available || channel->udp_fd < 0) {
                    continue;
                }
                if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
                    bpf2socks_udp_dns_close_channel(&state, channel, bpf2socks_now_ms());
                } else if ((events & EPOLLIN) != 0) {
                    bpf2socks_udp_dns_handle_upstream(&state, worker, channel, upstream_packets);
                }
            }
        }
        udp_run_maintenance(&state, worker, &next_stats_publish_ms);
    }

    publish_udp_stats_if_due(worker, bpf2socks_now_ms(), &next_stats_publish_ms, true);
    free(client_payloads);
    free(upstream_packets);
    free_state(&state);
    if (result != 0) errno = wait_errno;
    return result;
}
