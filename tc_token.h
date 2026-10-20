// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_TC_TOKEN_H
#define BPF2SOCKS_TC_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#define BPF2SOCKS_TC_RUNTIME_ENABLED 1U
#define BPF2SOCKS_TC_RUNTIME_IPV6 2U
#define BPF2SOCKS_TC_RUNTIME_DNS_HIJACK 4U
#define BPF2SOCKS_TC_RUNTIME_BYPASS_DIRECT 8U
#define BPF2SOCKS_TC_MAX_TOKEN_ATTEMPTS 2U
#define BPF2SOCKS_TC_SCRATCH_ABI_SIZE 224U
#define BPF2SOCKS_TC_FRAGMENT_MAP_ENTRIES 4096U
#define BPF2SOCKS_TC_FRAGMENT_PASS 0U
#define BPF2SOCKS_TC_FRAGMENT_REWRITE 1U

struct bpf2socks_tc_original_key {
    uint32_t ifindex;
    uint8_t family;
    uint8_t protocol;
    uint16_t reserved;
    uint8_t client_addr[16];
    uint16_t client_port;
    uint16_t original_port;
    uint8_t original_addr[16];
};

struct bpf2socks_tc_token_value {
    uint8_t token_addr[16];
    uint16_t token_port;
    uint16_t reserved;
    uint32_t generation;
};

struct bpf2socks_tc_reverse_key {
    uint32_t ifindex;
    uint8_t family;
    uint8_t protocol;
    uint16_t reserved;
    uint8_t client_addr[16];
    uint16_t client_port;
    uint16_t token_port;
    uint8_t token_addr[16];
};

struct bpf2socks_tc_original_value {
    uint8_t original_addr[16];
    uint16_t original_port;
    uint16_t reserved;
    uint32_t reserved_alignment;
    uint64_t created_at_ns;
    uint64_t last_seen_ns;
    uint32_t generation;
    uint32_t flags;
};

/*
 * One fragmented datagram from a hotspot client: only its first fragment
 * carries the ports, so the verdict taken there is replayed for the rest.
 * Addresses are the client source and the original destination; id is the
 * IPv4 identification or the IPv6 fragment header identification.
 */
struct bpf2socks_tc_fragment_key {
    uint32_t ifindex;
    uint8_t family;
    uint8_t protocol;
    uint16_t reserved;
    uint32_t id;
    uint8_t source[16];
    uint8_t destination[16];
};

struct bpf2socks_tc_fragment_value {
    uint8_t token_addr[16];
    uint32_t generation;
    uint32_t verdict;
};

struct bpf2socks_tc_runtime_control {
    uint32_t enabled;
    uint32_t generation;
    uint16_t bridge_port;
    uint16_t flags;
    uint8_t token_ipv4_prefix[4];
    uint8_t token_ipv6_prefix[16];
    uint32_t worker_count;
};

_Static_assert(sizeof(struct bpf2socks_tc_original_key) == 44U, "unexpected original key ABI");
_Static_assert(offsetof(struct bpf2socks_tc_original_key, client_addr) == 8U, "unexpected client address offset");
_Static_assert(offsetof(struct bpf2socks_tc_original_key, original_addr) == 28U, "unexpected original address offset");
_Static_assert(sizeof(struct bpf2socks_tc_token_value) == 24U, "unexpected token value ABI");
_Static_assert(sizeof(struct bpf2socks_tc_reverse_key) == 44U, "unexpected reverse key ABI");
_Static_assert(sizeof(struct bpf2socks_tc_original_value) == 48U, "unexpected original value ABI");
_Static_assert(offsetof(struct bpf2socks_tc_original_value, generation) == 40U, "unexpected generation offset");
_Static_assert(sizeof(struct bpf2socks_tc_runtime_control) == 36U, "unexpected runtime control ABI");
_Static_assert(sizeof(struct bpf2socks_tc_fragment_key) == 44U, "unexpected fragment key ABI");
_Static_assert(sizeof(struct bpf2socks_tc_fragment_value) == 24U, "unexpected fragment value ABI");

#endif
