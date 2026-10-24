// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BRIDGE_BRIDGE_H
#define BPF2SOCKS_BRIDGE_BRIDGE_H

#include "bpf2socks.h"

/* Runs the TCP and UDP workers until a stop is requested; 0 on a clean stop. */
int bpf2socks_bridge_run(const struct bpf2socks_runtime_config *config, const char *pid_path);

#endif
