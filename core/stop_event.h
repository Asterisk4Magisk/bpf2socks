// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_STOP_EVENT_H
#define BPF2SOCKS_CORE_STOP_EVENT_H

#include <stdbool.h>

/*
 * Process-wide stop request: signal handlers and failing threads set it, and
 * every poll loop watches the eventfd so it wakes at once.
 */
int bpf2socks_stop_event_init(void);
int bpf2socks_stop_event_fd(void);
void bpf2socks_stop_event_close(void);
bool bpf2socks_stop_requested(void);
void bpf2socks_stop_request(void);

#endif
