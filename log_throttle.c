// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "log_throttle.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

void bpf2socks_log_throttled(_Atomic uint64_t *counter, const char *format, ...) {
    uint64_t occurrence = atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed) + 1U;
    /* Log the 1st, 2nd, 4th, 8th... occurrence. */
    if ((occurrence & (occurrence - 1U)) != 0U) return;
    int saved_errno = errno;
    va_list args;
    va_start(args, format);
    (void)vfprintf(stderr, format, args);
    va_end(args);
    if (occurrence > 1U) (void)fprintf(stderr, " (occurrence %" PRIu64 ")", occurrence);
    (void)fputc('\n', stderr);
    errno = saved_errno;
}
