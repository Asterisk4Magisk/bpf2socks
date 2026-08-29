// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "udp_binding_index.h"

#include "bridge_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static uint64_t hash_bytes(uint64_t hash, const void *data, size_t length) {
    const uint8_t *bytes = data;
    for (size_t i = 0U; i < length; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t binding_hash(
    const struct bpf2socks_udp_client_session *owner,
    const struct bpf2socks_sockaddr *original) {
    uint64_t hash = 1469598103934665603ULL;
    uintptr_t owner_identity = (uintptr_t)owner;
    hash = hash_bytes(hash, &owner_identity, sizeof(owner_identity));
    hash = hash_bytes(hash, &original->family, sizeof(original->family));
    hash = hash_bytes(hash, &original->port, sizeof(original->port));
    size_t address_length = original->family == AF_INET6 ? 16U : 4U;
    return hash_bytes(hash, original->addr, address_length);
}

static bool same_key(
    const struct bpf2socks_udp_reply_binding *binding,
    const struct bpf2socks_udp_client_session *owner,
    const struct bpf2socks_sockaddr *original) {
    if (binding->owner != owner || binding->original_dst.family != original->family ||
        binding->original_dst.port != original->port) {
        return false;
    }
    size_t address_length = original->family == AF_INET6 ? 16U : 4U;
    return memcmp(binding->original_dst.addr, original->addr, address_length) == 0;
}

static bool valid_original(const struct bpf2socks_sockaddr *original) {
    return original != NULL && (original->family == AF_INET || original->family == AF_INET6);
}

int bpf2socks_udp_binding_index_init(
    struct bpf2socks_udp_binding_index *index,
    size_t capacity) {
    if (index == NULL || capacity == 0U) {
        errno = EINVAL;
        return -1;
    }
    memset(index, 0, sizeof(*index));
    size_t bucket_count = 1U;
    while (bucket_count < capacity) {
        if (bucket_count > SIZE_MAX / 2U) {
            errno = EOVERFLOW;
            return -1;
        }
        bucket_count *= 2U;
    }
    if (bucket_count > SIZE_MAX / sizeof(*index->buckets)) {
        errno = EOVERFLOW;
        return -1;
    }
    index->buckets = calloc(bucket_count, sizeof(*index->buckets));
    if (index->buckets == NULL) {
        errno = ENOMEM;
        return -1;
    }
    index->bucket_count = bucket_count;
    return 0;
}

void bpf2socks_udp_binding_index_free(struct bpf2socks_udp_binding_index *index) {
    if (index == NULL) return;
    if (index->buckets != NULL) {
        for (size_t i = 0U; i < index->bucket_count; ++i) {
            struct bpf2socks_udp_reply_binding *binding = index->buckets[i];
            while (binding != NULL) {
                struct bpf2socks_udp_reply_binding *next = binding->hash_next;
                binding->hash_next = NULL;
                binding = next;
            }
        }
    }
    free(index->buckets);
    memset(index, 0, sizeof(*index));
}

struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_index_find(
    const struct bpf2socks_udp_binding_index *index,
    const struct bpf2socks_udp_client_session *owner,
    const struct bpf2socks_sockaddr *original,
    uint64_t *collision_steps) {
    if (collision_steps != NULL) *collision_steps = 0U;
    if (index == NULL || index->buckets == NULL || index->bucket_count == 0U ||
        owner == NULL || !valid_original(original)) {
        return NULL;
    }
    size_t bucket = (size_t)(binding_hash(owner, original) & (index->bucket_count - 1U));
    uint64_t steps = 0U;
    for (struct bpf2socks_udp_reply_binding *binding = index->buckets[bucket];
         binding != NULL;
         binding = binding->hash_next) {
        if (binding->used && same_key(binding, owner, original)) {
            if (collision_steps != NULL) *collision_steps = steps;
            return binding;
        }
        ++steps;
    }
    if (collision_steps != NULL) *collision_steps = steps;
    return NULL;
}

int bpf2socks_udp_binding_index_insert(
    struct bpf2socks_udp_binding_index *index,
    struct bpf2socks_udp_reply_binding *binding) {
    if (index == NULL || index->buckets == NULL || index->bucket_count == 0U ||
        binding == NULL || !binding->used || binding->owner == NULL ||
        !valid_original(&binding->original_dst)) {
        errno = EINVAL;
        return -1;
    }
    size_t bucket = (size_t)(binding_hash(binding->owner, &binding->original_dst) &
        (index->bucket_count - 1U));
    for (struct bpf2socks_udp_reply_binding *current = index->buckets[bucket];
         current != NULL;
         current = current->hash_next) {
        if (current == binding) {
            errno = EEXIST;
            return -1;
        }
    }
    binding->hash_next = index->buckets[bucket];
    index->buckets[bucket] = binding;
    return 0;
}

bool bpf2socks_udp_binding_index_remove(
    struct bpf2socks_udp_binding_index *index,
    struct bpf2socks_udp_reply_binding *binding) {
    if (index == NULL || index->buckets == NULL || index->bucket_count == 0U ||
        binding == NULL || binding->owner == NULL || !valid_original(&binding->original_dst)) {
        return false;
    }
    size_t bucket = (size_t)(binding_hash(binding->owner, &binding->original_dst) &
        (index->bucket_count - 1U));
    struct bpf2socks_udp_reply_binding **slot = &index->buckets[bucket];
    while (*slot != NULL) {
        if (*slot == binding) {
            *slot = binding->hash_next;
            binding->hash_next = NULL;
            return true;
        }
        slot = &(*slot)->hash_next;
    }
    return false;
}
