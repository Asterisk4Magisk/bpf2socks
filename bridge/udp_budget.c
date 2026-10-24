// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bridge/udp_budget.h"
#include "bpf2socks.h"

#include <errno.h>
#include <unistd.h>

void bpf2socks_udp_budget_init(struct bpf2socks_udp_budget *budget, size_t cap_bytes) {
    if (budget == NULL) return;
    budget->cap_bytes = cap_bytes;
    atomic_init(&budget->used_bytes, 0U);
    atomic_init(&budget->peak_bytes, 0U);
    atomic_init(&budget->waiting_workers, 0U);
    for (uint32_t i = 0U; i < BPF2SOCKS_MAX_WORKER_COUNT; ++i) {
        atomic_init(&budget->wake_fds[i], -1);
    }
}

void bpf2socks_udp_budget_set_wake_fd(
    struct bpf2socks_udp_budget *budget,
    uint32_t worker_id,
    int fd) {
    if (budget == NULL || worker_id >= BPF2SOCKS_MAX_WORKER_COUNT) return;
    atomic_store_explicit(&budget->wake_fds[worker_id], fd, memory_order_release);
}

/* Register before re-checking the budget so a concurrent release cannot be missed. */
void bpf2socks_udp_budget_wait(struct bpf2socks_udp_budget *budget, uint32_t worker_id) {
    if (budget == NULL || worker_id >= BPF2SOCKS_MAX_WORKER_COUNT) return;
    (void)atomic_fetch_or_explicit(&budget->waiting_workers, 1U << worker_id, memory_order_acq_rel);
}

static void wake_pending_budget_waiters(struct bpf2socks_udp_budget *budget) {
    if (atomic_load_explicit(&budget->waiting_workers, memory_order_acquire) == 0U) return;
    unsigned int waiters = atomic_exchange_explicit(&budget->waiting_workers, 0U, memory_order_acq_rel);
    for (uint32_t i = 0U; waiters != 0U && i < BPF2SOCKS_MAX_WORKER_COUNT; ++i) {
        if ((waiters & (1U << i)) == 0U) continue;
        waiters &= ~(1U << i);
        int fd = atomic_load_explicit(&budget->wake_fds[i], memory_order_acquire);
        if (fd < 0) continue;
        uint64_t one = 1U;
        (void)write(fd, &one, sizeof(one));
    }
}

static void update_pending_budget_peak(struct bpf2socks_udp_budget *budget, size_t used_bytes) {
    size_t peak = atomic_load_explicit(&budget->peak_bytes, memory_order_relaxed);
    while (peak < used_bytes &&
        !atomic_compare_exchange_weak_explicit(
            &budget->peak_bytes,
            &peak,
            used_bytes,
            memory_order_relaxed,
            memory_order_relaxed)) {
    }
}

int bpf2socks_udp_budget_reserve(struct bpf2socks_udp_budget *budget, size_t bytes) {
    if (budget == NULL) {
        errno = EINVAL;
        return -1;
    }
    size_t used = atomic_load_explicit(&budget->used_bytes, memory_order_relaxed);
    for (;;) {
        if (bytes > budget->cap_bytes || used > budget->cap_bytes - bytes) {
            errno = ENOBUFS;
            return -1;
        }
        size_t next = used + bytes;
        if (atomic_compare_exchange_weak_explicit(
                &budget->used_bytes,
                &used,
                next,
                memory_order_acq_rel,
                memory_order_relaxed)) {
            update_pending_budget_peak(budget, next);
            return 0;
        }
    }
}

int bpf2socks_udp_budget_release(struct bpf2socks_udp_budget *budget, size_t bytes) {
    if (budget == NULL) {
        errno = EINVAL;
        return -1;
    }
    size_t used = atomic_load_explicit(&budget->used_bytes, memory_order_relaxed);
    for (;;) {
        if (bytes > used) {
            errno = ERANGE;
            return -1;
        }
        if (atomic_compare_exchange_weak_explicit(
                &budget->used_bytes,
                &used,
                used - bytes,
                memory_order_acq_rel,
                memory_order_relaxed)) {
            wake_pending_budget_waiters(budget);
            return 0;
        }
    }
}

size_t bpf2socks_udp_budget_used(const struct bpf2socks_udp_budget *budget) {
    return budget == NULL ? 0U : atomic_load_explicit(&budget->used_bytes, memory_order_relaxed);
}

size_t bpf2socks_udp_budget_peak(const struct bpf2socks_udp_budget *budget) {
    return budget == NULL ? 0U : atomic_load_explicit(&budget->peak_bytes, memory_order_relaxed);
}
