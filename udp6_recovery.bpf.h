// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

/* The UDP disconnect implementation on some kernels leaves sk_v6_daddr set.
 * A CONNECT token then filters out the real-source replies emitted by the
 * bridge. Remember the live token on loopback output and select the same
 * disconnected socket on input, without rewriting packet source addresses.
 * Map eviction only disables recovery; a map value is never a socket handle. */
struct udp6_recovery_key {
    __u32 address[4];
    __u32 port;
};
EXTERNAL_MAP(udp6_recovery_peers, struct udp6_recovery_key, __u8[16], 65536U);

static struct bpf_sock *(*recovery_fullsock)(struct bpf_sock *) =
    (void *)BPF_FUNC_sk_fullsock;
static struct bpf_sock *(*recovery_lookup)(void *, struct bpf_sock_tuple *, __u32, __u64, __u64) =
    (void *)BPF_FUNC_sk_lookup_udp;
static long (*recovery_assign)(void *, void *, __u64) = (void *)BPF_FUNC_sk_assign;
static void (*recovery_release)(void *) = (void *)BPF_FUNC_sk_release;
static long (*recovery_load)(void *, __u32, void *, __u32, __u32) =
    (void *)BPF_FUNC_skb_load_bytes_relative;

SEC("classifier/udp6_probe")
int bpf2socks_udp6_probe(struct __sk_buff *skb) {
    struct bpf_sock *sk = skb->sk;
    if (sk != 0) {
        sk = recovery_fullsock(sk);
        if (sk != 0) (void)recovery_assign(skb, sk, 0U);
    }
    return TC_ACT_PIPE;
}

INLINE const struct bpf2socks_tc_runtime_control *recovery_control(void) {
    __u32 zero = 0U;
    const struct bpf2socks_tc_runtime_control *control = map_lookup(&tc_runtime_control, &zero);
    if (control == 0 || control->enabled == 0U ||
        (control->flags & BPF2SOCKS_TC_RUNTIME_IPV6) == 0U) return 0;
    return control;
}

SEC("classifier/udp6_record")
int bpf2socks_udp6_record(struct __sk_buff *skb) {
    if (skb->protocol != swap16(ETH_P_IPV6)) return TC_ACT_PIPE;
    struct bpf_sock *sk = skb->sk;
    if (sk == 0) return TC_ACT_PIPE;
    sk = recovery_fullsock(sk);
    if (sk == 0 || sk->family != AF_INET6_VALUE || sk->protocol != IPPROTO_UDP_VALUE ||
        (sk->state != 1U && sk->state != 7U)) return TC_ACT_PIPE;
    const struct bpf2socks_tc_runtime_control *control = recovery_control();
    if (control == 0) return TC_ACT_PIPE;
    /* Explicit field loads avoid forbidden arithmetic on a verifier socket pointer. */
    __u32 peer[4] = {sk->dst_ip6[0], sk->dst_ip6[1], sk->dst_ip6[2], sk->dst_ip6[3]};
    if (!ipv6_in_token_prefix((const __u8 *)peer, control->token_ipv6_prefix)) return TC_ACT_PIPE;
    struct ipv6_header ip;
    if (recovery_load(skb, 0U, &ip, sizeof(ip), BPF_HDR_START_NET) != 0 ||
        (swap32(ip.version_flow) >> 28U) != 6U) return TC_ACT_PIPE;
    struct udp6_recovery_key key = {.port = sk->src_port};
    copy_bytes((__u8 *)key.address, ip.source, 16U);
    /* A lookup refreshes LRU use without rewriting an unchanged endpoint on
     * every packet. A reconnect or eviction still takes the update path. */
    const __u32 *previous = map_lookup(&udp6_recovery_peers, &key);
    if (previous != 0 && previous[0] == peer[0] && previous[1] == peer[1] &&
        previous[2] == peer[2] && previous[3] == peer[3]) return TC_ACT_PIPE;
    (void)map_update(&udp6_recovery_peers, &key, peer, BPF_ANY);
    return TC_ACT_PIPE;
}

SEC("classifier/udp6_recover")
int bpf2socks_udp6_recover(struct __sk_buff *skb) {
    if (skb->protocol != swap16(ETH_P_IPV6) || skb->sk != 0 || recovery_control() == 0) return TC_ACT_PIPE;
    struct ipv6_header ip;
    struct transport_ports ports;
    if (recovery_load(skb, 0U, &ip, sizeof(ip), BPF_HDR_START_NET) != 0 ||
        (swap32(ip.version_flow) >> 28U) != 6U || ip.next_header != IPPROTO_UDP_VALUE ||
        recovery_load(skb, sizeof(ip), &ports, sizeof(ports), BPF_HDR_START_NET) != 0) {
        return TC_ACT_PIPE;
    }
    struct udp6_recovery_key key = {.port = swap16(ports.destination)};
    copy_bytes((__u8 *)key.address, ip.destination, 16U);
    const __u8 *peer = map_lookup(&udp6_recovery_peers, &key);
    if (peer == 0) return TC_ACT_PIPE;
    struct bpf_sock_tuple tuple = {0};
    __u32 expected_peer[4];
    copy_bytes((__u8 *)expected_peer, peer, 16U);
    copy_bytes((__u8 *)tuple.ipv6.saddr, (const __u8 *)expected_peer, 16U);
    copy_bytes((__u8 *)tuple.ipv6.daddr, ip.destination, 16U);
    tuple.ipv6.sport = ports.source;
    tuple.ipv6.dport = ports.destination;
    struct bpf_sock *sk = recovery_lookup(skb, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0U);
    if (sk != 0) {
        /* Kernel lookup validates the live local tuple, bound interface and
         * token peer. Reconnect/close/port reuse therefore cannot revive a
         * stale entry. Never bypass a connected UDP socket's peer filter. */
        if (sk->state == 7U && sk->dst_port == 0U &&
            sk->dst_ip6[0] == expected_peer[0] && sk->dst_ip6[1] == expected_peer[1] &&
            sk->dst_ip6[2] == expected_peer[2] && sk->dst_ip6[3] == expected_peer[3]) {
            /* Only a live recovery candidate needs the second lookup. Keep
             * normal receivers ahead of recovery, including reused ports. */
            copy_bytes((__u8 *)tuple.ipv6.saddr, ip.source, 16U);
            struct bpf_sock *normal = recovery_lookup(skb, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0U);
            if (normal != 0) recovery_release(normal);
            else (void)recovery_assign(skb, sk, 0U);
        }
        recovery_release(sk);
    }
    return TC_ACT_PIPE;
}
