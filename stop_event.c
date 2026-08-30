// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf2socks.h"

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/eventfd.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "bpf2socks stop flag must be lock-free");

static _Atomic int stop_requested = 0;
static volatile sig_atomic_t stop_event_fd = -1;

int bpf2socks_stop_event_init(void) {
    if (stop_event_fd >= 0) {
        errno = EALREADY;
        return -1;
    }
    int fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) return -1;
    atomic_store_explicit(&stop_requested, 0, memory_order_relaxed);
    stop_event_fd = fd;
    return 0;
}

int bpf2socks_stop_event_fd(void) {
    return (int)stop_event_fd;
}

bool bpf2socks_stop_is_requested(void) {
    return atomic_load_explicit(&stop_requested, memory_order_relaxed) != 0;
}

void bpf2socks_request_stop(void) {
    int saved = errno;
    atomic_store_explicit(&stop_requested, 1, memory_order_relaxed);
    int fd = (int)stop_event_fd;
    if (fd >= 0) {
        uint64_t signal = 1U;
        ssize_t written;
        do {
            written = write(fd, &signal, sizeof(signal));
        } while (written < 0 && errno == EINTR);
    }
    errno = saved;
}

void bpf2socks_stop_event_close(void) {
    int fd = (int)stop_event_fd;
    stop_event_fd = -1;
    if (fd >= 0) close(fd);
}
