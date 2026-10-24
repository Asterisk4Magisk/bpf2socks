// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_TOKEN_H
#define BPF2SOCKS_CORE_TOKEN_H

#include "bpf2socks.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Cgroup tokens are published without a client address, while TC hotspot
 * tokens carry the client tuple. Local applications reach the bridge from
 * loopback, so their client-less key is the one to try first.
 */
bool bpf2socks_token_key_is_loopback(const struct bpf2socks_token_key *key);
int bpf2socks_token_lookup(int map_fd, const struct bpf2socks_token_key *key, struct bpf2socks_original_dst *out);
int bpf2socks_token_take(
    int map_fd,
    const struct bpf2socks_token_key *key,
    struct bpf2socks_original_dst *out,
    bool *delete_failed);
int bpf2socks_token_prefix_parse4(const char *text, uint8_t out[4], uint32_t *prefix_bits);
bool bpf2socks_token_prefix_match4(
    uint32_t addr_net,
    const uint8_t prefix[4],
    uint32_t prefix_bits);
uint32_t bpf2socks_token_prefix_imm4(const uint8_t prefix[4], uint32_t prefix_bits);
uint32_t bpf2socks_token_prefix_host_mask4(uint32_t prefix_bits);
int bpf2socks_token_prefix_parse6(const char *text, uint8_t out[16], uint32_t *prefix_bits);
bool bpf2socks_token_prefix_match6(
    const uint8_t addr[16],
    const uint8_t prefix[16],
    uint32_t prefix_bits);
uint32_t bpf2socks_token_prefix_word6(const uint8_t prefix[16], size_t offset);

enum bpf2socks_token_lookup_mode {
    BPF2SOCKS_TOKEN_LOOKUP_UNKNOWN = 0,
    BPF2SOCKS_TOKEN_LOOKUP_FULL_CLIENT,
    BPF2SOCKS_TOKEN_LOOKUP_ZERO_CLIENT,
};

struct bpf2socks_token_lookup_trace {
    enum bpf2socks_token_lookup_mode matched_mode;
    uint8_t full_client_attempts;
    uint8_t zero_client_attempts;
};

int bpf2socks_token_lookup_udp(
    int map_fd,
    const struct bpf2socks_token_key *full_key,
    enum bpf2socks_token_lookup_mode preference,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_token_lookup_trace *trace);

#endif
