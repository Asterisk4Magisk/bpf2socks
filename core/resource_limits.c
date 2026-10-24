// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "core/resource_limits.h"

#include <errno.h>
#include <limits.h>
#include <sys/resource.h>

#define BPF2SOCKS_TCP_FDS_PER_SESSION 6ULL
#define BPF2SOCKS_UDP_FDS_PER_SESSION 2ULL
#define BPF2SOCKS_UDP_FDS_PER_BINDING 1ULL

uint32_t bpf2socks_limits_worker_quota(uint32_t total, uint32_t worker_id, uint32_t worker_count) {
    if (worker_count == 0U || worker_id >= worker_count) return 0U;
    return total / worker_count + (worker_id < total % worker_count ? 1U : 0U);
}

static uint64_t session_fd_demand(
    uint32_t max_tcp_sessions,
    uint32_t max_udp_sessions,
    uint32_t max_udp_bindings) {
    uint64_t total = (uint64_t)max_tcp_sessions * BPF2SOCKS_TCP_FDS_PER_SESSION;
    total += (uint64_t)max_udp_sessions * BPF2SOCKS_UDP_FDS_PER_SESSION;
    total += (uint64_t)max_udp_bindings * BPF2SOCKS_UDP_FDS_PER_BINDING;
    return total;
}

int bpf2socks_limits_fit_session_capacity(
    uint64_t nofile_limit,
    uint64_t reserve_fds,
    struct bpf2socks_limits_capacity *capacity) {
    if (capacity == NULL || capacity->worker_count == 0U || capacity->max_tcp_sessions == 0U) {
        errno = EINVAL;
        return -1;
    }
    if (capacity->max_udp_sessions == 0U) {
        errno = EINVAL;
        return -1;
    }
    if (capacity->max_udp_bindings < capacity->max_udp_sessions) {
        capacity->max_udp_bindings = capacity->max_udp_sessions;
    }
    if (nofile_limit == UINT64_MAX) return 0;
    if (nofile_limit == 0U || nofile_limit <= reserve_fds) {
        errno = EMFILE;
        return -1;
    }

    uint64_t available_fds = nofile_limit - reserve_fds;
    uint64_t requested_fds = session_fd_demand(
        capacity->max_tcp_sessions,
        capacity->max_udp_sessions,
        capacity->max_udp_bindings);
    if (requested_fds <= available_fds) return 0;

    uint32_t tcp_sessions = (uint32_t)((uint64_t)capacity->max_tcp_sessions * available_fds / requested_fds);
    uint32_t udp_sessions =
        (uint32_t)((uint64_t)capacity->max_udp_sessions * available_fds / requested_fds);
    uint32_t udp_bindings =
        (uint32_t)((uint64_t)capacity->max_udp_bindings * available_fds / requested_fds);
    if (tcp_sessions < capacity->worker_count ||
        udp_sessions < capacity->worker_count ||
        udp_bindings < udp_sessions) {
        errno = EMFILE;
        return -1;
    }

    uint64_t used_fds = session_fd_demand(tcp_sessions, udp_sessions, udp_bindings);
    if (used_fds < available_fds) {
        uint64_t grow = available_fds - used_fds;
        uint64_t binding_room = (uint64_t)capacity->max_udp_bindings - udp_bindings;
        if (grow > binding_room) grow = binding_room;
        udp_bindings += (uint32_t)grow;
    }
    capacity->max_tcp_sessions = tcp_sessions;
    capacity->max_udp_sessions = udp_sessions;
    capacity->max_udp_bindings = udp_bindings;
    return 0;
}

int bpf2socks_limits_nofile_soft(uint64_t *out_limit) {
    if (out_limit == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return -1;
    *out_limit = limit.rlim_cur == RLIM_INFINITY ? UINT64_MAX : (uint64_t)limit.rlim_cur;
    return 0;
}

int bpf2socks_limits_raise_nofile(uint32_t requested_limit) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return -1;
    rlim_t target = (rlim_t)requested_limit;
    if (target > limit.rlim_max) target = limit.rlim_max;
    if (limit.rlim_cur >= target) return 0;
    limit.rlim_cur = target;
    return setrlimit(RLIMIT_NOFILE, &limit);
}

int bpf2socks_limits_raise_memlock(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) return -1;
    struct rlimit unlimited = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &unlimited) == 0) return 0;
    if (limit.rlim_cur >= limit.rlim_max) return 0;
    limit.rlim_cur = limit.rlim_max;
    return setrlimit(RLIMIT_MEMLOCK, &limit);
}
