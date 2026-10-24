// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_UTIL_H
#define BPF2SOCKS_CORE_UTIL_H

#include <stddef.h>
#include <stdint.h>

#define BPF2SOCKS_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* CLOCK_MONOTONIC in milliseconds; 0 when the clock cannot be read. */
uint64_t bpf2socks_now_ms(void);

/* 32-bit FNV-1a. */
uint32_t bpf2socks_hash_bytes(const void *data, size_t len);

/* Closes *fd when open and marks it closed (-1). */
void bpf2socks_close_fd(int *fd);

#endif
