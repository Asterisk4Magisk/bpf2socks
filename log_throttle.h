// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_LOG_THROTTLE_H
#define BPF2SOCKS_LOG_THROTTLE_H

#include <stdatomic.h>
#include <stdint.h>

/* Writes format plus a newline to stderr when the occurrence is due; keeps errno. */
void bpf2socks_log_throttled(_Atomic uint64_t *counter, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

/*
 * Logs a per-packet or per-connection failure on exponentially spaced
 * occurrences, so a persistent fault cannot flood the core log. The format
 * carries no trailing newline; later lines report the occurrence count.
 */
#define BPF2SOCKS_LOG_THROTTLED(...) \
    do { \
        static _Atomic uint64_t bpf2socks_log_throttle_counter_; \
        bpf2socks_log_throttled(&bpf2socks_log_throttle_counter_, __VA_ARGS__); \
    } while (0)

#endif
