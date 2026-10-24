// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BRIDGE_UDP_BUDGET_H
#define BPF2SOCKS_BRIDGE_UDP_BUDGET_H

#include "bpf2socks.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Memory shared by every worker for UDP datagrams queued in userspace, both
 * uplink (waiting for an ASSOCIATE) and downlink (waiting for a client).
 */
struct bpf2socks_udp_budget {
    size_t cap_bytes;
    atomic_size_t used_bytes;
    atomic_size_t peak_bytes;
    /* Workers blocked on the budget and their eventfds, woken on release. */
    atomic_uint waiting_workers;
    atomic_int wake_fds[BPF2SOCKS_MAX_WORKER_COUNT];
};
void bpf2socks_udp_budget_init(struct bpf2socks_udp_budget *budget, size_t cap_bytes);
int bpf2socks_udp_budget_reserve(struct bpf2socks_udp_budget *budget, size_t bytes);
int bpf2socks_udp_budget_release(struct bpf2socks_udp_budget *budget, size_t bytes);
size_t bpf2socks_udp_budget_used(const struct bpf2socks_udp_budget *budget);
size_t bpf2socks_udp_budget_peak(const struct bpf2socks_udp_budget *budget);
void bpf2socks_udp_budget_set_wake_fd(
    struct bpf2socks_udp_budget *budget,
    uint32_t worker_id,
    int fd);
void bpf2socks_udp_budget_wait(struct bpf2socks_udp_budget *budget, uint32_t worker_id);

#endif
