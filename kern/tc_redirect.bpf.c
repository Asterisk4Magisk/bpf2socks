// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "tc_token.h"
#include "tc_checksum_flags.h"
#include "tc_packet_layout.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline))

#define ETH_P_IP 0x0800U
#define ETH_P_IPV6 0x86ddU
#define IPPROTO_TCP_VALUE 6U
#define IPPROTO_UDP_VALUE 17U
#define IKE_PORT 500U
#define NAT_T_PORT 4500U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IP_FRAGMENT_MASK 0x3fffU
#define IP_OFFSET_MASK 0x1fffU
#define IPV6_FRAGMENT_HEADER 44U
#define IPV6_FRAGMENT_OFFSET_MASK 0xfff8U
#define SK_PASS_VALUE 1

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct bpf2socks_lpm4_key_bpf {
    __u32 prefixlen;
    __u32 addr;
};

struct bpf2socks_lpm6_key_bpf {
    __u32 prefixlen;
    __u8 addr[16];
};

struct bpf2socks_token_key_bpf {
    __u8 family;
    __u8 protocol;
    __u16 token_port;
    __u8 token_addr[16];
    __u16 client_port;
    __u16 reserved;
    __u8 client_addr[16];
};

struct bpf2socks_original_dst_bpf {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 addr[16];
    __u8 flags;
    __u8 reserved[3];
};

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct ipv6_fragment_header {
    __u8 next_header;
    __u8 reserved;
    __be16 offset_flags;
    __be32 id;
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct bpf2socks_tc_scratch {
    struct bpf2socks_tc_original_key original;
    struct bpf2socks_tc_token_value token;
    struct bpf2socks_token_key_bpf bridge_key;
    struct bpf2socks_original_dst_bpf bridge_value;
    struct bpf2socks_tc_reverse_key reverse_key;
    struct bpf2socks_tc_original_value reverse_value;
};

_Static_assert(sizeof(struct bpf2socks_tc_scratch) == BPF2SOCKS_TC_SCRATCH_ABI_SIZE, "tc scratch ABI");

#define EXTERNAL_MAP(name, key_type, value_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = BPF_MAP_TYPE_HASH, \
        .key_size = sizeof(key_type), \
        .value_size = sizeof(value_type), \
        .max_entries = entries, \
    }

EXTERNAL_MAP(tc_runtime_control, __u32, struct bpf2socks_tc_runtime_control, 1U);
EXTERNAL_MAP(tc_original_to_token, struct bpf2socks_tc_original_key, struct bpf2socks_tc_token_value, 65536U);
EXTERNAL_MAP(tc_token_to_original, struct bpf2socks_tc_reverse_key, struct bpf2socks_tc_original_value, 65536U);
EXTERNAL_MAP(bridge_token_map, struct bpf2socks_token_key_bpf, struct bpf2socks_original_dst_bpf, 65536U);
EXTERNAL_MAP(proxy_cidr4_map, struct bpf2socks_lpm4_key_bpf, __u8, 512U);
EXTERNAL_MAP(bypass_private_cidr4_map, struct bpf2socks_lpm4_key_bpf, __u8, 512U);
EXTERNAL_MAP(local_interface_cidr4_map, struct bpf2socks_lpm4_key_bpf, __u8, 512U);
EXTERNAL_MAP(direct_cidr4_map, struct bpf2socks_lpm4_key_bpf, __u8, 32768U);
EXTERNAL_MAP(proxy_cidr6_map, struct bpf2socks_lpm6_key_bpf, __u8, 512U);
EXTERNAL_MAP(bypass_private_cidr6_map, struct bpf2socks_lpm6_key_bpf, __u8, 512U);
EXTERNAL_MAP(local_interface_cidr6_map, struct bpf2socks_lpm6_key_bpf, __u8, 512U);
EXTERNAL_MAP(direct_cidr6_map, struct bpf2socks_lpm6_key_bpf, __u8, 32768U);
EXTERNAL_MAP(reuseport_tcp4, __u32, __u64, 8U);
EXTERNAL_MAP(reuseport_udp4, __u32, __u64, 8U);
EXTERNAL_MAP(reuseport_tcp6, __u32, __u64, 8U);
EXTERNAL_MAP(reuseport_udp6, __u32, __u64, 8U);
EXTERNAL_MAP(tc_fragment_map, struct bpf2socks_tc_fragment_key, struct bpf2socks_tc_fragment_value,
    BPF2SOCKS_TC_FRAGMENT_MAP_ENTRIES);
struct bpf_map_def SEC("maps") tc_scratch = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct bpf2socks_tc_scratch),
    .max_entries = 1U,
};

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*skb_pull_data)(struct __sk_buff *skb, __u32 length) = (void *)BPF_FUNC_skb_pull_data;
static long (*skb_store_bytes)(
    struct __sk_buff *skb,
    __u32 offset,
    const void *from,
    __u32 length,
    __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static long (*l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l3_csum_replace;
static long (*l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
static long (*select_reuseport)(
    struct sk_reuseport_md *reuse,
    void *map,
    void *key,
    __u64 flags) = (void *)BPF_FUNC_sk_select_reuseport;

INLINE __u16 swap16(__u16 value) {
    return __builtin_bswap16(value);
}

INLINE __u32 swap32(__u32 value) {
    return __builtin_bswap32(value);
}

INLINE void copy_bytes(__u8 *destination, const __u8 *source, __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        if (index < size) destination[index] = source[index];
    }
}

INLINE bool equal_bytes(const __u8 *left, const __u8 *right, __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        if (index < size && left[index] != right[index]) return false;
    }
    return true;
}

INLINE __u32 hash_original(const struct bpf2socks_tc_original_key *key, __u32 salt) {
    const __u8 *bytes = (const __u8 *)key;
    __u32 hash = 2166136261U ^ salt;
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < sizeof(*key); ++index) {
        hash ^= bytes[index];
        hash *= 16777619U;
    }
    hash ^= hash >> 16U;
    hash *= 0x7feb352dU;
    hash ^= hash >> 15U;
    hash *= 0x846ca68bU;
    hash ^= hash >> 16U;
    return hash;
}

INLINE bool ipv4_in_token_prefix(__be32 address, const __u8 prefix[4]) {
    __u32 host = swap32(address);
    __u32 prefix_host =
        ((__u32)prefix[0] << 24U) |
        ((__u32)prefix[1] << 16U) |
        ((__u32)prefix[2] << 8U) |
        (__u32)prefix[3];
    return (host & 0xff800000U) == (prefix_host & 0xff800000U);
}

INLINE bool ipv6_in_token_prefix(const __u8 address[16], const __u8 prefix[16]) {
    return equal_bytes(address, prefix, 8U);
}

INLINE bool policy4_proxy(__be32 destination, __u8 protocol, __u16 destination_port, __u16 flags) {
    if (protocol == IPPROTO_UDP_VALUE &&
        (destination_port == IKE_PORT || destination_port == NAT_T_PORT)) return false;
    if ((flags & BPF2SOCKS_TC_RUNTIME_DNS_HIJACK) != 0U &&
        (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) && destination_port == 53U) {
        return true;
    }
    struct bpf2socks_lpm4_key_bpf key = {.prefixlen = 32U, .addr = destination};
    if (map_lookup(&local_interface_cidr4_map, &key) != 0) return false;
    if (map_lookup(&proxy_cidr4_map, &key) != 0) return true;
    if (map_lookup(&bypass_private_cidr4_map, &key) != 0) return false;
    if ((flags & BPF2SOCKS_TC_RUNTIME_BYPASS_DIRECT) != 0U &&
        map_lookup(&direct_cidr4_map, &key) != 0) {
        return false;
    }
    return true;
}

INLINE bool policy6_proxy(const __u8 destination[16], __u8 protocol, __u16 destination_port, __u16 flags) {
    if (protocol == IPPROTO_UDP_VALUE &&
        (destination_port == IKE_PORT || destination_port == NAT_T_PORT)) return false;
    if ((flags & BPF2SOCKS_TC_RUNTIME_DNS_HIJACK) != 0U &&
        (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) && destination_port == 53U) {
        return true;
    }
    struct bpf2socks_lpm6_key_bpf key = {.prefixlen = 128U};
    copy_bytes(key.addr, destination, 16U);
    if (map_lookup(&local_interface_cidr6_map, &key) != 0) return false;
    if (map_lookup(&proxy_cidr6_map, &key) != 0) return true;
    if (map_lookup(&bypass_private_cidr6_map, &key) != 0) return false;
    if ((flags & BPF2SOCKS_TC_RUNTIME_BYPASS_DIRECT) != 0U &&
        map_lookup(&direct_cidr6_map, &key) != 0) {
        return false;
    }
    return true;
}

INLINE void fill_bridge_key(
    struct bpf2socks_token_key_bpf *key,
    const struct bpf2socks_tc_original_key *original,
    const struct bpf2socks_tc_token_value *token) {
    __builtin_memset(key, 0, sizeof(*key));
    key->family = original->family;
    key->protocol = original->protocol;
    key->token_port = token->token_port;
    key->client_port = original->client_port;
    copy_bytes(key->token_addr, token->token_addr, original->family == AF_INET6_VALUE ? 16U : 4U);
    copy_bytes(key->client_addr, original->client_addr, original->family == AF_INET6_VALUE ? 16U : 4U);
}

INLINE void fill_reverse_key(
    struct bpf2socks_tc_reverse_key *key,
    const struct bpf2socks_tc_original_key *original,
    const struct bpf2socks_tc_token_value *token) {
    __builtin_memset(key, 0, sizeof(*key));
    key->ifindex = original->ifindex;
    key->family = original->family;
    key->protocol = original->protocol;
    key->client_port = original->client_port;
    key->token_port = token->token_port;
    copy_bytes(key->client_addr, original->client_addr, original->family == AF_INET6_VALUE ? 16U : 4U);
    copy_bytes(key->token_addr, token->token_addr, original->family == AF_INET6_VALUE ? 16U : 4U);
}

INLINE void fill_bridge_value(
    struct bpf2socks_original_dst_bpf *value,
    const struct bpf2socks_tc_original_key *original) {
    __builtin_memset(value, 0, sizeof(*value));
    value->family = original->family;
    value->protocol = original->protocol;
    value->port = original->original_port;
    copy_bytes(value->addr, original->original_addr, original->family == AF_INET6_VALUE ? 16U : 4U);
}

INLINE bool is_tcp_syn(const void *l4, const void *data_end) {
    const struct tcp_header_min *tcp = l4;
    if ((const void *)(tcp + 1) > data_end) return false;
    return (swap16(tcp->flags) & 0x0012U) == 0x0002U;
}

INLINE bool find_reserved_token(
    const struct bpf2socks_tc_original_key *original,
    const struct bpf2socks_tc_runtime_control *control,
    struct bpf2socks_tc_scratch *scratch) {
    struct bpf2socks_tc_token_value *existing = map_lookup(&tc_original_to_token, original);
    if (existing == 0 || existing->generation != control->generation) return false;
    scratch->token = *existing;
    return true;
}

INLINE bool allocate_token(
    const struct bpf2socks_tc_original_key *original,
    const struct bpf2socks_tc_runtime_control *control,
    struct bpf2socks_tc_scratch *scratch) {
    struct bpf2socks_tc_token_value *token = &scratch->token;

#pragma clang loop unroll(full)
    for (__u32 attempt = 0U; attempt < BPF2SOCKS_TC_MAX_TOKEN_ATTEMPTS; ++attempt) {
        __builtin_memset(token, 0, sizeof(*token));
        __u32 hash = hash_original(original, 0x9e3779b9U * attempt);
        token->token_port = control->bridge_port;
        token->generation = control->generation;
        if (original->family == AF_INET_VALUE) {
            __u32 prefix =
                ((__u32)control->token_ipv4_prefix[0] << 24U) |
                ((__u32)control->token_ipv4_prefix[1] << 16U) |
                ((__u32)control->token_ipv4_prefix[2] << 8U) |
                control->token_ipv4_prefix[3];
            __u32 host_mask = 0x007fffffU;
            __u32 candidate = (prefix & 0xff800000U) | (hash & host_mask);
            if ((candidate & 0xffffff00U) == (prefix & 0xffffff00U) ||
                (candidate & host_mask) == host_mask) {
                continue;
            }
            token->token_addr[0] = (__u8)(candidate >> 24U);
            token->token_addr[1] = (__u8)(candidate >> 16U);
            token->token_addr[2] = (__u8)(candidate >> 8U);
            token->token_addr[3] = (__u8)candidate;
        } else {
            copy_bytes(token->token_addr, control->token_ipv6_prefix, 8U);
            __u32 second_hash = hash_original(original, 0x85ebca6bU ^ attempt);
            token->token_addr[8] = (__u8)(hash >> 24U);
            token->token_addr[9] = (__u8)(hash >> 16U);
            token->token_addr[10] = (__u8)(hash >> 8U);
            token->token_addr[11] = (__u8)hash;
            token->token_addr[12] = (__u8)(second_hash >> 24U);
            token->token_addr[13] = (__u8)(second_hash >> 16U);
            token->token_addr[14] = (__u8)(second_hash >> 8U);
            token->token_addr[15] = (__u8)second_hash;
        }

        struct bpf2socks_token_key_bpf *bridge_key = &scratch->bridge_key;
        struct bpf2socks_original_dst_bpf *bridge_value = &scratch->bridge_value;
        fill_bridge_key(bridge_key, original, token);
        fill_bridge_value(bridge_value, original);
        if (map_update(&bridge_token_map, bridge_key, bridge_value, BPF_NOEXIST) != 0) continue;

        struct bpf2socks_tc_reverse_key *reverse_key = &scratch->reverse_key;
        struct bpf2socks_tc_original_value *reverse_value = &scratch->reverse_value;
        fill_reverse_key(reverse_key, original, token);
        __u64 now = ktime_get_ns();
        __builtin_memset(reverse_value, 0, sizeof(*reverse_value));
        reverse_value->original_port = original->original_port;
        reverse_value->created_at_ns = now;
        reverse_value->last_seen_ns = now;
        reverse_value->generation = control->generation;
        copy_bytes(
            reverse_value->original_addr,
            original->original_addr,
            original->family == AF_INET6_VALUE ? 16U : 4U);
        if (map_update(&tc_token_to_original, reverse_key, reverse_value, BPF_NOEXIST) != 0) {
            map_delete(&bridge_token_map, bridge_key);
            continue;
        }
        if (map_update(&tc_original_to_token, original, token, BPF_ANY) != 0) {
            map_delete(&tc_token_to_original, reverse_key);
            map_delete(&bridge_token_map, bridge_key);
            return false;
        }
        return true;
    }
    return false;
}

/*
 * The bridge consumes a TCP bridge_token_map entry when it accepts the
 * connection, while the flow's token stays remembered here. A client that
 * reuses its source port for the same destination would then reach the
 * bridge without an original destination, so each new SYN republishes it.
 */
INLINE bool republish_bridge_token(
    const struct bpf2socks_tc_original_key *original,
    struct bpf2socks_tc_scratch *scratch) {
    fill_bridge_key(&scratch->bridge_key, original, &scratch->token);
    fill_bridge_value(&scratch->bridge_value, original);
    return map_update(&bridge_token_map, &scratch->bridge_key, &scratch->bridge_value, BPF_ANY) == 0;
}

INLINE int rewrite_ipv4(
    struct __sk_buff *skb,
    __u32 address_offset,
    __u32 port_offset,
    __u32 checksum_offset,
    __be32 old_address,
    __be32 new_address,
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    bool is_udp = protocol == IPPROTO_UDP_VALUE;
    __u32 ip_checksum_offset = sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv4_header, checksum);
    if (l3_csum_replace(skb, ip_checksum_offset, old_address, new_address, 4U) != 0 ||
        l4_csum_replace(
            skb,
            checksum_offset,
            old_address,
            new_address,
            bpf2socks_l4_address_flags(is_udp, 4U)) != 0 ||
        l4_csum_replace(
            skb,
            checksum_offset,
            old_port,
            new_port,
            bpf2socks_l4_port_flags(is_udp, 2U)) != 0) {
        return TC_ACT_SHOT;
    }
    if (skb_store_bytes(skb, address_offset, &new_address, sizeof(new_address), 0U) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE void fill_fragment_key(
    struct bpf2socks_tc_fragment_key *key,
    __u32 ifindex,
    __u8 family,
    __u8 protocol,
    __u32 id,
    const __u8 *source,
    const __u8 *destination,
    __u32 address_size) {
    __builtin_memset(key, 0, sizeof(*key));
    key->ifindex = ifindex;
    key->family = family;
    key->protocol = protocol;
    key->id = id;
    copy_bytes(key->source, source, address_size);
    copy_bytes(key->destination, destination, address_size);
}

/*
 * Records a first fragment's verdict for the later fragments of its datagram.
 * The key is built here from the header fields rather than carried on the
 * stack from an earlier branch: older verifiers (GKI 5.10) cannot tie the two
 * "is a first fragment" branches together and reject the possibly
 * uninitialized key.
 */
INLINE void remember_fragment(
    __u32 ifindex,
    __u8 family,
    __u8 protocol,
    __u32 id,
    const __u8 *source,
    const __u8 *destination,
    __u32 address_size,
    const __u8 *token_addr,
    __u32 verdict,
    __u32 generation) {
    struct bpf2socks_tc_fragment_key key;
    fill_fragment_key(&key, ifindex, family, protocol, id, source, destination, address_size);
    struct bpf2socks_tc_fragment_value value;
    __builtin_memset(&value, 0, sizeof(value));
    if (token_addr != 0) copy_bytes(value.token_addr, token_addr, 16U);
    value.generation = generation;
    value.verdict = verdict;
    (void)map_update(&tc_fragment_map, &key, &value, BPF_ANY);
}

/*
 * Later fragments carry no ports. They follow the verdict of their first
 * fragment; without one the datagram is dropped rather than forwarded past
 * the proxy. Only the destination address changes, and the transport
 * checksum lives in the first fragment.
 */
INLINE int ingress4_later_fragment(
    struct __sk_buff *skb,
    struct ipv4_header *ip,
    const struct bpf2socks_tc_runtime_control *control) {
    if (ip->protocol != IPPROTO_TCP_VALUE && ip->protocol != IPPROTO_UDP_VALUE) return TC_ACT_PIPE;
    struct bpf2socks_tc_fragment_key key;
    fill_fragment_key(&key, skb->ifindex, AF_INET_VALUE, ip->protocol, ip->id,
        (const __u8 *)&ip->source, (const __u8 *)&ip->destination, 4U);
    struct bpf2socks_tc_fragment_value *fragment = map_lookup(&tc_fragment_map, &key);
    if (fragment == 0 || fragment->generation != control->generation) return TC_ACT_SHOT;
    if (fragment->verdict != BPF2SOCKS_TC_FRAGMENT_REWRITE) return TC_ACT_PIPE;
    __be32 token_address;
    __builtin_memcpy(&token_address, fragment->token_addr, 4U);
    if (l3_csum_replace(
            skb,
            sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv4_header, checksum),
            ip->destination,
            token_address,
            4U) != 0 ||
        skb_store_bytes(
            skb,
            sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv4_header, destination),
            &token_address,
            sizeof(token_address),
            0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int ingress4(
    struct __sk_buff *skb,
    struct ipv4_header *ip,
    void *data_end,
    const struct bpf2socks_tc_runtime_control *control) {
    if (ip->version != 4U || ip->ihl < 5U) return TC_ACT_SHOT;
    __u32 header_length = (__u32)ip->ihl * 4U;
    __u16 fragment_bits = swap16(ip->fragment_offset) & IP_FRAGMENT_MASK;
    if ((fragment_bits & IP_OFFSET_MASK) != 0U) return ingress4_later_fragment(skb, ip, control);
    if ((void *)ip + header_length + sizeof(struct transport_ports) > data_end) return TC_ACT_SHOT;
    if (ip->protocol != IPPROTO_TCP_VALUE && ip->protocol != IPPROTO_UDP_VALUE) return TC_ACT_PIPE;
    if ((swap32(ip->destination) & 0xff000000U) == 0x7f000000U) return TC_ACT_SHOT;
    /* More-fragments with offset zero: the first fragment, which carries the ports. */
    bool first_fragment = fragment_bits != 0U;
    struct transport_ports *ports = (void *)ip + header_length;
    __u16 destination_port = swap16(ports->destination);
    bool tcp_syn = ip->protocol == IPPROTO_TCP_VALUE && is_tcp_syn(ports, data_end);

    __u32 zero = 0U;
    struct bpf2socks_tc_scratch *scratch = map_lookup(&tc_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct bpf2socks_tc_original_key *original = &scratch->original;
    __builtin_memset(original, 0, sizeof(*original));
    original->ifindex = skb->ifindex;
    original->family = AF_INET_VALUE;
    original->protocol = ip->protocol;
    original->client_port = swap16(ports->source);
    original->original_port = destination_port;
    copy_bytes(original->client_addr, (__u8 *)&ip->source, 4U);
    copy_bytes(original->original_addr, (__u8 *)&ip->destination, 4U);
    /* An existing token means policy already admitted this flow; skip the LPM lookups. */
    if (!find_reserved_token(original, control, scratch)) {
        if (!policy4_proxy(ip->destination, ip->protocol, destination_port, control->flags) ||
            !allocate_token(original, control, scratch)) {
            if (first_fragment) {
                remember_fragment(skb->ifindex, AF_INET_VALUE, ip->protocol, ip->id,
                    (const __u8 *)&ip->source, (const __u8 *)&ip->destination, 4U,
                    0, BPF2SOCKS_TC_FRAGMENT_PASS, control->generation);
            }
            return TC_ACT_PIPE;
        }
    } else if (tcp_syn && !republish_bridge_token(original, scratch)) {
        return TC_ACT_PIPE;
    }
    if (first_fragment) {
        remember_fragment(skb->ifindex, AF_INET_VALUE, ip->protocol, ip->id,
            (const __u8 *)&ip->source, (const __u8 *)&ip->destination, 4U,
            scratch->token.token_addr, BPF2SOCKS_TC_FRAGMENT_REWRITE, control->generation);
    }

    __be32 token_address;
    __builtin_memcpy(&token_address, scratch->token.token_addr, 4U);
    __u32 l4_offset = sizeof(struct ethernet_header) + header_length;
    __u32 checksum_offset = l4_offset +
        (ip->protocol == IPPROTO_TCP_VALUE
            ? __builtin_offsetof(struct tcp_header_min, checksum)
            : __builtin_offsetof(struct udp_header_min, checksum));
    return rewrite_ipv4(
        skb,
        sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv4_header, destination),
        l4_offset + __builtin_offsetof(struct transport_ports, destination),
        checksum_offset,
        ip->destination,
        token_address,
        ports->destination,
        swap16(control->bridge_port),
        ip->protocol);
}

INLINE int egress4(
    struct __sk_buff *skb,
    struct ipv4_header *ip,
    void *data_end,
    const struct bpf2socks_tc_runtime_control *control) {
    if (ip->version != 4U || ip->ihl < 5U) return TC_ACT_SHOT;
    __u32 header_length = (__u32)ip->ihl * 4U;
    if ((void *)ip + header_length + sizeof(struct transport_ports) > data_end) return TC_ACT_SHOT;
    if (!ipv4_in_token_prefix(ip->source, control->token_ipv4_prefix)) return TC_ACT_PIPE;
    if ((swap16(ip->fragment_offset) & IP_FRAGMENT_MASK) != 0U) return TC_ACT_SHOT;
    if (ip->protocol != IPPROTO_TCP_VALUE && ip->protocol != IPPROTO_UDP_VALUE) return TC_ACT_SHOT;
    struct transport_ports *ports = (void *)ip + header_length;
    if (swap16(ports->source) != control->bridge_port) return TC_ACT_SHOT;

    __u32 zero = 0U;
    struct bpf2socks_tc_scratch *scratch = map_lookup(&tc_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct bpf2socks_tc_reverse_key *key = &scratch->reverse_key;
    __builtin_memset(key, 0, sizeof(*key));
    key->ifindex = skb->ifindex;
    key->family = AF_INET_VALUE;
    key->protocol = ip->protocol;
    key->client_port = swap16(ports->destination);
    key->token_port = control->bridge_port;
    copy_bytes(key->client_addr, (__u8 *)&ip->destination, 4U);
    copy_bytes(key->token_addr, (__u8 *)&ip->source, 4U);
    struct bpf2socks_tc_original_value *original = map_lookup(&tc_token_to_original, key);
    if (original == 0 || original->generation != control->generation) return TC_ACT_SHOT;
    original->last_seen_ns = ktime_get_ns();
    __be32 original_address;
    __builtin_memcpy(&original_address, original->original_addr, 4U);
    __u32 l4_offset = sizeof(struct ethernet_header) + header_length;
    __u32 checksum_offset = l4_offset +
        (ip->protocol == IPPROTO_TCP_VALUE
            ? __builtin_offsetof(struct tcp_header_min, checksum)
            : __builtin_offsetof(struct udp_header_min, checksum));
    return rewrite_ipv4(
        skb,
        sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv4_header, source),
        l4_offset + __builtin_offsetof(struct transport_ports, source),
        checksum_offset,
        ip->source,
        original_address,
        ports->source,
        swap16(original->original_port),
        ip->protocol);
}

INLINE int rewrite_ipv6(
    struct __sk_buff *skb,
    __u32 address_offset,
    __u32 port_offset,
    __u32 checksum_offset,
    const __u8 old_address[16],
    const __u8 new_address[16],
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    bool is_udp = protocol == IPPROTO_UDP_VALUE;
#pragma clang loop unroll(full)
    for (__u32 offset = 0U; offset < 16U; offset += 4U) {
        __be32 old_word;
        __be32 new_word;
        __builtin_memcpy(&old_word, old_address + offset, 4U);
        __builtin_memcpy(&new_word, new_address + offset, 4U);
        if (l4_csum_replace(
                skb,
                checksum_offset,
                old_word,
                new_word,
                bpf2socks_l4_address_flags(is_udp, 4U)) != 0) {
            return TC_ACT_SHOT;
        }
    }
    if (l4_csum_replace(
            skb,
            checksum_offset,
            old_port,
            new_port,
            bpf2socks_l4_port_flags(is_udp, 2U)) != 0 ||
        skb_store_bytes(skb, address_offset, new_address, 16U, 0U) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int ingress6_later_fragment(
    struct __sk_buff *skb,
    const struct bpf2socks_tc_fragment_key *key,
    const struct bpf2socks_tc_runtime_control *control) {
    struct bpf2socks_tc_fragment_value *fragment = map_lookup(&tc_fragment_map, key);
    if (fragment == 0 || fragment->generation != control->generation) {
        /* With IPv6 proxying off only port 53 is redirected; leave other datagrams alone. */
        return (control->flags & BPF2SOCKS_TC_RUNTIME_IPV6) != 0U ? TC_ACT_SHOT : TC_ACT_PIPE;
    }
    if (fragment->verdict != BPF2SOCKS_TC_FRAGMENT_REWRITE) return TC_ACT_PIPE;
    if (skb_store_bytes(
            skb,
            sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv6_header, destination),
            fragment->token_addr,
            16U,
            0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int ingress6(
    struct __sk_buff *skb,
    struct ipv6_header *ip,
    void *data_end,
    const struct bpf2socks_tc_runtime_control *control) {
    if ((swap32(ip->version_flow) >> 28U) != 6U) return TC_ACT_SHOT;
    __u8 protocol = ip->next_header;
    void *l4 = (void *)(ip + 1);
    __u32 l4_offset = sizeof(struct ethernet_header) + sizeof(struct ipv6_header);
    bool first_fragment = false;
    __u32 fragment_id = 0U;
    if (protocol == IPV6_FRAGMENT_HEADER) {
        struct ipv6_fragment_header *fragment = l4;
        if ((void *)(fragment + 1) > data_end) return TC_ACT_SHOT;
        protocol = fragment->next_header;
        if (protocol != IPPROTO_TCP_VALUE && protocol != IPPROTO_UDP_VALUE) return TC_ACT_PIPE;
        fragment_id = fragment->id;
        if ((swap16(fragment->offset_flags) & IPV6_FRAGMENT_OFFSET_MASK) != 0U) {
            struct bpf2socks_tc_fragment_key key;
            fill_fragment_key(&key, skb->ifindex, AF_INET6_VALUE, protocol, fragment_id,
                ip->source, ip->destination, 16U);
            return ingress6_later_fragment(skb, &key, control);
        }
        first_fragment = true;
        l4 = (void *)(fragment + 1);
        l4_offset += sizeof(struct ipv6_fragment_header);
    }
    if (protocol != IPPROTO_TCP_VALUE && protocol != IPPROTO_UDP_VALUE) return TC_ACT_PIPE;
    if (l4 + sizeof(struct transport_ports) > data_end) return TC_ACT_SHOT;
    if (ipv6_in_token_prefix(ip->destination, control->token_ipv6_prefix)) return TC_ACT_SHOT;
    struct transport_ports *ports = l4;
    __u16 destination_port = swap16(ports->destination);
    bool tcp_syn = protocol == IPPROTO_TCP_VALUE && is_tcp_syn(ports, data_end);
    if ((control->flags & BPF2SOCKS_TC_RUNTIME_IPV6) == 0U &&
        ((control->flags & BPF2SOCKS_TC_RUNTIME_DNS_HIJACK) == 0U || destination_port != 53U)) {
        if (first_fragment) {
            remember_fragment(skb->ifindex, AF_INET6_VALUE, protocol, fragment_id,
                ip->source, ip->destination, 16U, 0, BPF2SOCKS_TC_FRAGMENT_PASS, control->generation);
        }
        return TC_ACT_PIPE;
    }

    __u32 zero = 0U;
    struct bpf2socks_tc_scratch *scratch = map_lookup(&tc_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct bpf2socks_tc_original_key *original = &scratch->original;
    __builtin_memset(original, 0, sizeof(*original));
    original->ifindex = skb->ifindex;
    original->family = AF_INET6_VALUE;
    original->protocol = protocol;
    original->client_port = swap16(ports->source);
    original->original_port = destination_port;
    copy_bytes(original->client_addr, ip->source, 16U);
    copy_bytes(original->original_addr, ip->destination, 16U);
    /* An existing token means policy already admitted this flow; skip the LPM lookups. */
    if (!find_reserved_token(original, control, scratch)) {
        if (!policy6_proxy(ip->destination, protocol, destination_port, control->flags) ||
            !allocate_token(original, control, scratch)) {
            if (first_fragment) {
                remember_fragment(skb->ifindex, AF_INET6_VALUE, protocol, fragment_id,
                    ip->source, ip->destination, 16U, 0, BPF2SOCKS_TC_FRAGMENT_PASS, control->generation);
            }
            return TC_ACT_PIPE;
        }
    } else if (tcp_syn && !republish_bridge_token(original, scratch)) {
        return TC_ACT_PIPE;
    }
    if (first_fragment) {
        remember_fragment(skb->ifindex, AF_INET6_VALUE, protocol, fragment_id,
            ip->source, ip->destination, 16U,
            scratch->token.token_addr, BPF2SOCKS_TC_FRAGMENT_REWRITE, control->generation);
    }
    __u32 checksum_offset = l4_offset +
        (protocol == IPPROTO_TCP_VALUE
            ? __builtin_offsetof(struct tcp_header_min, checksum)
            : __builtin_offsetof(struct udp_header_min, checksum));
    return rewrite_ipv6(
        skb,
        sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv6_header, destination),
        l4_offset + __builtin_offsetof(struct transport_ports, destination),
        checksum_offset,
        original->original_addr,
        scratch->token.token_addr,
        swap16(destination_port),
        swap16(control->bridge_port),
        original->protocol);
}

INLINE int egress6(
    struct __sk_buff *skb,
    struct ipv6_header *ip,
    void *data_end,
    const struct bpf2socks_tc_runtime_control *control) {
    if ((control->flags & (BPF2SOCKS_TC_RUNTIME_IPV6 | BPF2SOCKS_TC_RUNTIME_DNS_HIJACK)) == 0U) return TC_ACT_PIPE;
    if ((swap32(ip->version_flow) >> 28U) != 6U) return TC_ACT_SHOT;
    if (!ipv6_in_token_prefix(ip->source, control->token_ipv6_prefix)) return TC_ACT_PIPE;
    if (ip->next_header != IPPROTO_TCP_VALUE && ip->next_header != IPPROTO_UDP_VALUE) return TC_ACT_SHOT;
    if ((void *)(ip + 1) + sizeof(struct transport_ports) > data_end) return TC_ACT_SHOT;
    struct transport_ports *ports = (void *)(ip + 1);
    if (swap16(ports->source) != control->bridge_port) return TC_ACT_SHOT;

    __u32 zero = 0U;
    struct bpf2socks_tc_scratch *scratch = map_lookup(&tc_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct bpf2socks_tc_reverse_key *key = &scratch->reverse_key;
    __builtin_memset(key, 0, sizeof(*key));
    key->ifindex = skb->ifindex;
    key->family = AF_INET6_VALUE;
    key->protocol = ip->next_header;
    key->client_port = swap16(ports->destination);
    key->token_port = control->bridge_port;
    copy_bytes(key->client_addr, ip->destination, 16U);
    copy_bytes(key->token_addr, ip->source, 16U);
    struct bpf2socks_tc_original_value *original = map_lookup(&tc_token_to_original, key);
    if (original == 0 || original->generation != control->generation) return TC_ACT_SHOT;
    original->last_seen_ns = ktime_get_ns();
    __u32 l4_offset = sizeof(struct ethernet_header) + sizeof(struct ipv6_header);
    __u32 checksum_offset = l4_offset +
        (ip->next_header == IPPROTO_TCP_VALUE
            ? __builtin_offsetof(struct tcp_header_min, checksum)
            : __builtin_offsetof(struct udp_header_min, checksum));
    return rewrite_ipv6(
        skb,
        sizeof(struct ethernet_header) + __builtin_offsetof(struct ipv6_header, source),
        l4_offset + __builtin_offsetof(struct transport_ports, source),
        checksum_offset,
        key->token_addr,
        original->original_addr,
        swap16(control->bridge_port),
        swap16(original->original_port),
        key->protocol);
}

INLINE int classify(struct __sk_buff *skb, bool ingress) {
    __u32 zero = 0U;
    struct bpf2socks_tc_runtime_control *control = map_lookup(&tc_runtime_control, &zero);
    if (control == 0 || control->enabled == 0U) return TC_ACT_PIPE;
    if (skb_pull_data(skb, 0U) != 0) return TC_ACT_PIPE;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return TC_ACT_SHOT;
    __u16 protocol = swap16(ethernet->protocol);
    if (protocol == ETH_P_IP) {
        struct ipv4_header *ip = (void *)(ethernet + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
        return ingress ? ingress4(skb, ip, data_end, control) : egress4(skb, ip, data_end, control);
    }
    if (protocol == ETH_P_IPV6) {
        struct ipv6_header *ip = (void *)(ethernet + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
        return ingress ? ingress6(skb, ip, data_end, control) : egress6(skb, ip, data_end, control);
    }
    return TC_ACT_PIPE;
}

SEC("classifier/ingress")
int bpf2socks_tc_ingress(struct __sk_buff *skb) {
    return classify(skb, true);
}

SEC("classifier/egress")
int bpf2socks_tc_egress(struct __sk_buff *skb) {
    return classify(skb, false);
}

INLINE __u32 reuseport_index(const struct sk_reuseport_md *reuse, __u32 worker_count) {
    if (worker_count == 0U) return 0U;
    return reuse->hash % worker_count;
}

SEC("sk_reuseport")
int bpf2socks_reuseport(struct sk_reuseport_md *reuse) {
    __u32 zero = 0U;
    struct bpf2socks_tc_runtime_control *control = map_lookup(&tc_runtime_control, &zero);
    if (control == 0 || control->worker_count == 0U) return SK_PASS_VALUE;
    __u32 key = reuseport_index(reuse, control->worker_count);
    if (reuse->ip_protocol == IPPROTO_UDP_VALUE) {
        const __be16 *source_port = (const __be16 *)(long)reuse->data;
        const void *data_end = (const void *)(long)reuse->data_end;
        if ((const void *)(source_port + 1) > data_end) return SK_PASS_VALUE;
        /*
         * sk_reuseport_md does not expose remote addresses. Source-port
         * sharding deliberately over-groups clients but guarantees that one
         * client UDP endpoint cannot move workers when its token target changes.
         */
        key = (__u32)swap16(*source_port) % control->worker_count;
    }
    void *map = 0;
    if ((__u16)reuse->eth_protocol == swap16(ETH_P_IP)) {
        map = reuse->ip_protocol == IPPROTO_UDP_VALUE ? (void *)&reuseport_udp4 : (void *)&reuseport_tcp4;
    } else if ((__u16)reuse->eth_protocol == swap16(ETH_P_IPV6)) {
        map = reuse->ip_protocol == IPPROTO_UDP_VALUE ? (void *)&reuseport_udp6 : (void *)&reuseport_tcp6;
    } else {
        return SK_PASS_VALUE;
    }
    (void)select_reuseport(reuse, map, &key, 0U);
    return SK_PASS_VALUE;
}

#include "udp6_recovery.bpf.h"

char _license[] SEC("license") = "GPL";
