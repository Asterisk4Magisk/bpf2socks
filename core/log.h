// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_LOG_H
#define BPF2SOCKS_CORE_LOG_H

#include <stdatomic.h>
#include <stdint.h>

/*
 * Every diagnostic line goes to stderr as "bpf2socks: <message>\n", so the
 * supervisor's core log tells this helper apart. The format carries no
 * prefix and no trailing newline. errno is preserved.
 */
void bpf2socks_log(const char *format, ...) __attribute__((format(printf, 1, 2)));

/* bpf2socks_log() for the occurrence counter's due occurrences only. */
void bpf2socks_log_throttled(_Atomic uint64_t *counter, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

/*
 * Logs a per-packet or per-connection failure on exponentially spaced
 * occurrences, so a persistent fault cannot flood the core log. Later lines
 * report the occurrence count.
 */
#define BPF2SOCKS_LOG_THROTTLED(...) \
    do { \
        static _Atomic uint64_t bpf2socks_log_throttle_counter_; \
        bpf2socks_log_throttled(&bpf2socks_log_throttle_counter_, __VA_ARGS__); \
    } while (0)

#endif
