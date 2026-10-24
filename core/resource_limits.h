// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_RESOURCE_LIMITS_H
#define BPF2SOCKS_CORE_RESOURCE_LIMITS_H

#include <stdint.h>

int bpf2socks_limits_raise_nofile(uint32_t requested_limit);
int bpf2socks_limits_raise_memlock(void);

struct bpf2socks_limits_capacity {
    uint32_t worker_count;
    uint32_t max_tcp_sessions;
    uint32_t max_udp_sessions;
    uint32_t max_udp_bindings;
};

int bpf2socks_limits_fit_session_capacity(
    uint64_t nofile_limit,
    uint64_t reserve_fds,
    struct bpf2socks_limits_capacity *capacity);
int bpf2socks_limits_nofile_soft(uint64_t *out_limit);

uint32_t bpf2socks_limits_worker_quota(uint32_t total, uint32_t worker_id, uint32_t worker_count);

#endif
