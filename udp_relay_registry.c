// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#include "udp_relay_registry.h"

#include <stddef.h>

bool bpf2socks_udp_relay_port_claim(struct bpf2socks_udp_relay_registry *registry, uint16_t port) {
    if (registry == NULL) return true;
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(
        &registry->live[port], &expected, true, memory_order_acq_rel, memory_order_acquire);
}

void bpf2socks_udp_relay_port_release(struct bpf2socks_udp_relay_registry *registry, uint16_t port) {
    if (registry == NULL) return;
    atomic_store_explicit(&registry->live[port], false, memory_order_release);
}
