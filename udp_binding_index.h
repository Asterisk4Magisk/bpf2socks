// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_UDP_BINDING_INDEX_H
#define BPF2SOCKS_UDP_BINDING_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct bpf2socks_sockaddr;
struct bpf2socks_udp_client_session;
struct bpf2socks_udp_reply_binding;

struct bpf2socks_udp_binding_index {
    struct bpf2socks_udp_reply_binding **buckets;
    size_t bucket_count;
};

int bpf2socks_udp_binding_index_init(
    struct bpf2socks_udp_binding_index *index,
    size_t capacity);
void bpf2socks_udp_binding_index_free(struct bpf2socks_udp_binding_index *index);
struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_index_find(
    const struct bpf2socks_udp_binding_index *index,
    const struct bpf2socks_udp_client_session *owner,
    const struct bpf2socks_sockaddr *original,
    uint64_t *collision_steps);
int bpf2socks_udp_binding_index_insert(
    struct bpf2socks_udp_binding_index *index,
    struct bpf2socks_udp_reply_binding *binding);
bool bpf2socks_udp_binding_index_remove(
    struct bpf2socks_udp_binding_index *index,
    struct bpf2socks_udp_reply_binding *binding);

#endif
