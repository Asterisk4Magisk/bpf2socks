// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_UDP_RELAY_REGISTRY_H
#define BPF2SOCKS_UDP_RELAY_REGISTRY_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* ASSOCIATE retries for a session whose relay port is taken; then it is used as is. */
#define BPF2SOCKS_UDP_RELAY_PORT_MAX_RETRIES 3U

/*
 * Relay ports of every live UDP ASSOCIATE across all workers. A SOCKS5 server
 * that binds each association's relay socket to port 0 with SO_REUSEPORT (Xray)
 * can hand out a port that another live association still holds; the kernel
 * then delivers datagrams of one association to the other's socket. Owning a
 * port here means no other association of this bridge uses it.
 */
struct bpf2socks_udp_relay_registry {
    atomic_bool live[65536];
};

bool bpf2socks_udp_relay_port_claim(struct bpf2socks_udp_relay_registry *registry, uint16_t port);
void bpf2socks_udp_relay_port_release(struct bpf2socks_udp_relay_registry *registry, uint16_t port);

#endif
