// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_PROBE_H
#define BPF2SOCKS_CORE_PROBE_H

#include <stddef.h>

/*
 * Kernel capability probes run before any BPF state is touched. Each returns
 * 0 with "ok" in message, or -1 with the unavailable feature in message.
 */
int bpf2socks_probe_splice(char *message, size_t message_size);
int bpf2socks_probe_tcp_options(char *message, size_t message_size);

#endif
