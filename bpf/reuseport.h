// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BPF_REUSEPORT_H
#define BPF2SOCKS_BPF_REUSEPORT_H

#include "bpf2socks.h"

#include <stdint.h>

int bpf2socks_reuseport_register_worker(
    const struct bpf2socks_runtime_config *config,
    uint32_t worker_id,
    int tcp4_fd,
    int udp4_fd,
    int tcp6_fd,
    int udp6_fd);

#endif
