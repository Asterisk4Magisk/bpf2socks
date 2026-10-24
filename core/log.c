// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "core/log.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

#define BPF2SOCKS_LOG_PREFIX "bpf2socks: "

/* One fprintf per line keeps lines from concurrent threads whole. */
static void log_line(uint64_t occurrence, const char *format, va_list args) {
    char message[1024];
    (void)vsnprintf(message, sizeof(message), format, args);
    if (occurrence > 1U) {
        (void)fprintf(stderr, BPF2SOCKS_LOG_PREFIX "%s (occurrence %" PRIu64 ")\n", message, occurrence);
    } else {
        (void)fprintf(stderr, BPF2SOCKS_LOG_PREFIX "%s\n", message);
    }
}

void bpf2socks_log(const char *format, ...) {
    int saved_errno = errno;
    va_list args;
    va_start(args, format);
    log_line(0U, format, args);
    va_end(args);
    errno = saved_errno;
}

void bpf2socks_log_throttled(_Atomic uint64_t *counter, const char *format, ...) {
    uint64_t occurrence = atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed) + 1U;
    /* Log the 1st, 2nd, 4th, 8th... occurrence. */
    if ((occurrence & (occurrence - 1U)) != 0U) return;
    int saved_errno = errno;
    va_list args;
    va_start(args, format);
    log_line(occurrence, format, args);
    va_end(args);
    errno = saved_errno;
}
