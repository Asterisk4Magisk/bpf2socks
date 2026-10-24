// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bridge/internal.h"

#include <limits.h>

bool bpf2socks_deadline_tcp_expired(
    uint64_t now_ms,
    uint64_t created_at_ms,
    uint64_t last_activity_ms,
    bool relay_established,
    uint32_t connect_timeout_ms,
    uint32_t idle_timeout_ms) {
    if (now_ms == 0U) return false;
    if (!relay_established) {
        if (created_at_ms == 0U) return false;
        return connect_timeout_ms != 0U && now_ms >= created_at_ms &&
            now_ms - created_at_ms >= (uint64_t)connect_timeout_ms;
    }
    if (last_activity_ms == 0U) return false;
    return idle_timeout_ms != 0U && now_ms >= last_activity_ms &&
        now_ms - last_activity_ms >= (uint64_t)idle_timeout_ms;
}

void bpf2socks_deadline_note(uint64_t *next_deadline_ms, uint64_t deadline_ms) {
    if (next_deadline_ms != NULL && deadline_ms < *next_deadline_ms) *next_deadline_ms = deadline_ms;
}

/* epoll_wait() timeout until the deadline; -1 (no wakeup) without one. */
static int deadline_wait_timeout(uint64_t next_deadline_ms, uint64_t now_ms) {
    if (next_deadline_ms == BPF2SOCKS_NO_DEADLINE) return -1;
    if (now_ms == 0U || next_deadline_ms <= now_ms) return 0;
    uint64_t remaining = next_deadline_ms - now_ms;
    return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

static int min_wait_timeout(int timeout, int cap) {
    return timeout < 0 || timeout > cap ? cap : timeout;
}

int bpf2socks_deadline_tcp_wait_timeout(
    bool listeners_paused,
    uint64_t next_deadline_ms,
    uint64_t now_ms,
    bool debug_stats) {
    int timeout = deadline_wait_timeout(next_deadline_ms, now_ms);
    if (listeners_paused) timeout = min_wait_timeout(timeout, BPF2SOCKS_TCP_FD_BACKOFF_MILLISECONDS);
    if (debug_stats) timeout = min_wait_timeout(timeout, BPF2SOCKS_WORKER_TIMED_WAIT_MILLISECONDS);
    return timeout;
}

int bpf2socks_deadline_udp_wait_timeout(
    uint64_t next_deadline_ms,
    uint64_t now_ms,
    bool debug_stats) {
    int timeout = deadline_wait_timeout(next_deadline_ms, now_ms);
    if (debug_stats) timeout = min_wait_timeout(timeout, BPF2SOCKS_WORKER_TIMED_WAIT_MILLISECONDS);
    return timeout;
}
