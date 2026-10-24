// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "core/util.h"

#include <time.h>
#include <unistd.h>

uint64_t bpf2socks_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0U;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

uint32_t bpf2socks_hash_bytes(const void *data, size_t len) {
    const uint8_t *ptr = data;
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < len; ++i) {
        hash ^= ptr[i];
        hash *= 16777619U;
    }
    return hash;
}

void bpf2socks_close_fd(int *fd) {
    if (fd != NULL && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}
