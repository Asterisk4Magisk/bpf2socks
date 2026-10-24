// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/udp_destroy_events.h"
#include "bridge/udp_internal.h"
#include "core/log.h"
#include "core/socket_util.h"

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

/* Releases local sessions whose client socket the kernel reported destroyed. */


/* A local client reaches the bridge from the loopback address of its own socket. */
static bool session_client_is_local(const struct bpf2socks_udp_client_session *session) {
    return bpf2socks_sockaddr_is_loopback(&session->client_addr);
}

static uint16_t session_client_port(const struct bpf2socks_udp_client_session *session) {
    if (session->client_addr.ss_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)&session->client_addr)->sin6_port);
    }
    return ntohs(((const struct sockaddr_in *)&session->client_addr)->sin_port);
}

/*
 * A local client's session otherwise outlives its socket by the whole idle
 * timeout, and every one of them keeps a live UDP association in the SOCKS5
 * server. Short request/response sockets (STUN, NTP, resolvers that bypass the
 * DNS fast path) pile up thousands of them, and cores degrade with that count:
 * Xray already loses about 1% of datagrams on new associations with a few
 * hundred alive. The kernel reports every destroyed UDP socket; a session
 * whose port no socket holds any more is released. TC hotspot clients are
 * remote and keep the idle timeout.
 */
static void flag_all_local_sessions(struct bpf2socks_udp_state *state) {
    for (struct bpf2socks_udp_client_session *session = state->lru_head;
         session != NULL && session->used;
         session = session->lru_next) {
        if (session_client_is_local(session)) {
            bpf2socks_udp_port_bitmap_set(state->released_ports, session_client_port(session));
        }
    }
}

#define BPF2SOCKS_UDP_RELEASE_PORT_MEMO_SLOTS 256U

/* Per-pass memo, so sessions sharing a port cost one sock_diag query. */
struct release_port_results {
    uint16_t ports[BPF2SOCKS_UDP_RELEASE_PORT_MEMO_SLOTS];
    int8_t open[BPF2SOCKS_UDP_RELEASE_PORT_MEMO_SLOTS];
    size_t count;
};

static int release_port_has_socket(
    struct release_port_results *results,
    struct bpf2socks_bridge_worker *worker,
    uint16_t port) {
    for (size_t i = 0U; i < results->count; ++i) {
        if (results->ports[i] == port) return results->open[i];
    }
    ++worker->udp_stats.udp_release_confirm_queries;
    int open = bpf2socks_udp_destroy_events_port_open(port);
    if (results->count < BPF2SOCKS_UDP_RELEASE_PORT_MEMO_SLOTS) {
        results->ports[results->count] = port;
        results->open[results->count] = (int8_t)open;
        ++results->count;
    }
    return open;
}

/* Releases flagged local sessions whose port no UDP socket holds; clears the flags. */
static void release_flagged_sessions(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms) {
    struct release_port_results results;
    results.count = 0U;
    struct bpf2socks_udp_client_session *session = state->lru_head;
    while (session != NULL && session->used) {
        struct bpf2socks_udp_client_session *next = session->lru_next;
        uint16_t port = session_client_port(session);
        if (!session_client_is_local(session) ||
            !bpf2socks_udp_port_bitmap_has(state->released_ports, port)) {
            session = next;
            continue;
        }
        if (session->downlink_pending_count > 0U || session->downlink_waiting_budget) {
            /* Replies still drain to the old socket's port: decide once they are done. */
            session->release_retry_ms = now_ms + BPF2SOCKS_UDP_RELEASE_RETRY_MILLISECONDS;
            bpf2socks_deadline_note(&state->release_retry_due_ms, session->release_retry_ms);
            session = next;
            continue;
        }
        int open = release_port_has_socket(&results, worker, port);
        if (open == 0) {
            bpf2socks_udp_token_delete_closed_client(worker, session);
            bpf2socks_udp_session_drop(state, session);
            ++worker->udp_stats.udp_closed_client_releases;
        } else if (open < 0) {
            BPF2SOCKS_LOG_THROTTLED("UDP closed-client check failed: errno=%d", errno);
        }
        session = next;
    }
    memset(state->released_ports, 0, BPF2SOCKS_UDP_PORT_BITMAP_BYTES);
}

/* Records when each port in released_ports was last reported destroyed. */
static void stamp_destroyed_ports(struct bpf2socks_udp_state *state, uint64_t now_ms) {
    /* 0 means never, so a stamp that wraps to 0 is moved by one millisecond. */
    uint32_t stamp = (uint32_t)now_ms == 0U ? 1U : (uint32_t)now_ms;
    for (size_t word = 0U; word < BPF2SOCKS_UDP_PORT_BITMAP_BYTES / sizeof(uint64_t); ++word) {
        uint64_t bits;
        memcpy(&bits, state->released_ports + word * sizeof(uint64_t), sizeof(bits));
        while (bits != 0U) {
            unsigned bit = (unsigned)__builtin_ctzll(bits);
            bits &= bits - 1U;
            /* Bitmap byte i, bit j is port i * 8 + j; a little-endian word keeps that order. */
            state->port_destroyed_ms[word * 64U + bit] = stamp;
        }
    }
}

void bpf2socks_udp_release_handle_events(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms) {
    bool lost = false;
    size_t count = bpf2socks_udp_destroy_events_drain(state->destroy_events_fd, state->released_ports, &lost);
    worker->udp_stats.udp_release_events += count;
    if (count == 0U && !lost) return;
    if (count > 0U) stamp_destroyed_ports(state, now_ms);
    if (lost) {
        /* Some closes went unreported: check every local session instead. */
        ++worker->udp_stats.udp_release_events_lost;
        flag_all_local_sessions(state);
        state->check_new_sessions_until_ms = now_ms + BPF2SOCKS_UDP_RELEASE_RECENT_MILLISECONDS;
    }
    release_flagged_sessions(state, worker, now_ms);
}

/* Watches notifications again and handles those queued while unwatched. */
void bpf2socks_udp_release_arm(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms) {
    if (bpf2socks_udp_epoll_modify(state, state->destroy_events_fd, &state->destroy_events_ref, EPOLLIN) != 0) {
        BPF2SOCKS_LOG_THROTTLED("failed to watch UDP destroy notifications: errno=%d", errno);
    }
    state->destroy_events_armed = true;
    bpf2socks_udp_release_handle_events(state, worker, now_ms);
}

/* Stops wakeups for other apps' closes while no local session could match one. */
void bpf2socks_udp_release_disarm_if_idle(struct bpf2socks_udp_state *state) {
    if (!state->destroy_events_armed || state->local_session_count > 0U) return;
    if (bpf2socks_udp_epoll_modify(state, state->destroy_events_fd, &state->destroy_events_ref, 0U) == 0) {
        state->destroy_events_armed = false;
    }
}

/*
 * A session created from a datagram its client sent just before closing gets
 * no notification of its own any more: check it once, shortly after creation.
 */
void bpf2socks_udp_release_note_new_session(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    uint64_t now_ms) {
    if (!session_client_is_local(session)) return;
    uint32_t destroyed_ms = state->port_destroyed_ms[session_client_port(session)];
    bool recent = destroyed_ms != 0U &&
        (uint32_t)((uint32_t)now_ms - destroyed_ms) < BPF2SOCKS_UDP_RELEASE_RECENT_MILLISECONDS;
    if (!recent && now_ms >= state->check_new_sessions_until_ms) return;
    session->release_retry_ms = now_ms + BPF2SOCKS_UDP_RELEASE_RETRY_MILLISECONDS;
    bpf2socks_deadline_note(&state->release_retry_due_ms, session->release_retry_ms);
}

/* Re-checks sessions that were still delivering replies when their client closed. */
void bpf2socks_udp_release_retry(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms) {
    if (now_ms == 0U || now_ms < state->release_retry_due_ms) return;
    state->release_retry_due_ms = BPF2SOCKS_NO_DEADLINE;
    bool flagged = false;
    for (struct bpf2socks_udp_client_session *session = state->lru_head;
         session != NULL && session->used;
         session = session->lru_next) {
        if (session->release_retry_ms == 0U) continue;
        if (session->release_retry_ms > now_ms) {
            bpf2socks_deadline_note(&state->release_retry_due_ms, session->release_retry_ms);
            continue;
        }
        session->release_retry_ms = 0U;
        bpf2socks_udp_port_bitmap_set(state->released_ports, session_client_port(session));
        flagged = true;
    }
    if (flagged) release_flagged_sessions(state, worker, now_ms);
}
