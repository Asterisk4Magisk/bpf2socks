// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf/syscall.h"
#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/udp_internal.h"
#include "core/log.h"
#include "core/original_dst.h"
#include "core/socket_util.h"
#include "core/token.h"
#include "core/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Original destinations of client datagrams: token map lookups and their cache. */

static struct bpf2socks_udp_token_cache_entry *udp_token_cache_slot(
    struct bpf2socks_udp_state *state,
    const struct bpf2socks_token_key *key) {
    if (state->token_cache == NULL) {
        state->token_cache = calloc(BPF2SOCKS_UDP_TOKEN_CACHE_SIZE, sizeof(*state->token_cache));
        if (state->token_cache == NULL) return NULL;
    }
    uint32_t hash = bpf2socks_hash_bytes(key, sizeof(*key));
    return &state->token_cache[hash & (BPF2SOCKS_UDP_TOKEN_CACHE_SIZE - 1U)];
}

int bpf2socks_udp_token_lookup_original(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_packet *packet,
    enum bpf2socks_token_lookup_mode preference,
    uint64_t now_ms) {
    const struct bpf2socks_runtime_config *config = worker->config;
    struct bpf2socks_token_key key;
    struct bpf2socks_original_dst original;
    memset(&key, 0, sizeof(key));
    key.family = (uint8_t)packet->token_family;
    key.protocol = BPF2SOCKS_PROTO_UDP;
    key.token_port = config->listen_port;
    memcpy(key.token_addr, packet->token_addr, packet->token_family == AF_INET6 ? 16U : 4U);
    if (packet->client_addr.ss_family == AF_INET) {
        const struct sockaddr_in *client = (const struct sockaddr_in *)&packet->client_addr;
        key.client_port = ntohs(client->sin_port);
        memcpy(key.client_addr, &client->sin_addr, 4);
    } else if (packet->client_addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *client = (const struct sockaddr_in6 *)&packet->client_addr;
        key.client_port = ntohs(client->sin6_port);
        memcpy(key.client_addr, &client->sin6_addr, 16);
    }
    struct bpf2socks_udp_token_cache_entry *cached = udp_token_cache_slot(state, &key);
    if (cached != NULL && cached->expires_ms > now_ms &&
        memcmp(&cached->key, &key, sizeof(key)) == 0) {
        packet->token_lookup_mode = cached->mode;
        packet->connected_udp_token =
            (cached->original.flags & BPF2SOCKS_ORIGINAL_DST_FLAG_CONNECTED_UDP) != 0U;
        return bpf2socks_original_dst_to_sockaddr(&cached->original, &packet->original_dst);
    }
    struct bpf2socks_token_lookup_trace trace;
    int lookup_result = bpf2socks_token_lookup_udp(
            config->token_map_fd,
            &key,
            preference,
            &original,
            &trace);
    worker->udp_stats.udp_token_lookup_full_attempts += trace.full_client_attempts;
    worker->udp_stats.udp_token_lookup_zero_attempts += trace.zero_client_attempts;
    if (trace.matched_mode == BPF2SOCKS_TOKEN_LOOKUP_FULL_CLIENT) {
        ++worker->udp_stats.udp_token_lookup_full_hits;
    } else if (trace.matched_mode == BPF2SOCKS_TOKEN_LOOKUP_ZERO_CLIENT) {
        ++worker->udp_stats.udp_token_lookup_zero_hits;
    }
    if (trace.full_client_attempts != 0U && trace.zero_client_attempts != 0U) {
        ++worker->udp_stats.udp_token_lookup_fallbacks;
    }
    if (lookup_result < 0) {
        if (packet->has_original_dst) {
            packet->original_from_socket = true;
            return 0;
        }
        return -1;
    }
    packet->token_lookup_mode = trace.matched_mode;
    packet->connected_udp_token =
        (original.flags & BPF2SOCKS_ORIGINAL_DST_FLAG_CONNECTED_UDP) != 0U;
    if (cached != NULL && now_ms != 0U) {
        cached->key = key;
        cached->original = original;
        cached->mode = trace.matched_mode;
        cached->expires_ms = now_ms + BPF2SOCKS_UDP_TOKEN_CACHE_TTL_MILLISECONDS;
    }
    return bpf2socks_original_dst_to_sockaddr(&original, &packet->original_dst);
}

static void fill_client_less_udp_token_key(
    struct bpf2socks_token_key *key,
    int family,
    const uint8_t *token_addr,
    uint16_t listen_port) {
    memset(key, 0, sizeof(*key));
    key->family = (uint8_t)family;
    key->protocol = BPF2SOCKS_PROTO_UDP;
    key->token_port = listen_port;
    memcpy(key->token_addr, token_addr, family == AF_INET6 ? 16U : 4U);
}

/*
 * The token map is an LRU shared by every flow, and a connected socket that
 * sends and receives without addresses never refreshes its entry, so heavy
 * churn can evict it. When this client's session still holds the connected
 * binding for the token, take the original destination from it and publish
 * the token again so the recvmsg and getpeername hooks keep translating it.
 */
int bpf2socks_udp_token_recover_connected(
    struct bpf2socks_bridge_worker *worker,
    const struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_client_packet *packet) {
    if (session == NULL) return -1;
    size_t token_len = packet->token_family == AF_INET6 ? 16U : 4U;
    for (const struct bpf2socks_udp_reply_binding *binding = session->bindings;
         binding != NULL;
         binding = binding->next) {
        if (!binding->used || !binding->connected_udp_token ||
            memcmp(binding->token_addr, packet->token_addr, token_len) != 0) {
            continue;
        }
        packet->original_dst = binding->original_dst;
        packet->connected_udp_token = true;
        packet->token_lookup_mode = session->token_lookup_mode;
        struct bpf2socks_token_key key;
        fill_client_less_udp_token_key(&key, packet->token_family, packet->token_addr, worker->config->listen_port);
        struct bpf2socks_original_dst original;
        memset(&original, 0, sizeof(original));
        original.family = binding->original_dst.family;
        original.protocol = BPF2SOCKS_PROTO_UDP;
        original.port = binding->original_dst.port;
        memcpy(original.addr, binding->original_dst.addr, sizeof(original.addr));
        original.flags = BPF2SOCKS_ORIGINAL_DST_FLAG_CONNECTED_UDP;
        if (bpf2socks_bpf_map_update(worker->config->token_map_fd, &key, &original) != 0) {
            BPF2SOCKS_LOG_THROTTLED("failed to republish connected UDP token: errno=%d", errno);
        }
        return 0;
    }
    return -1;
}

/*
 * A local datagram whose token is unknown cannot be forwarded: its token was
 * evicted with its session, or it predates this bridge instance. Answer it
 * with an ICMP port unreachable that quotes the datagram, which the kernel
 * maps back to the sending socket: a connected socket then fails with
 * ECONNREFUSED and its application reconnects instead of waiting on a
 * silent black hole. Unconnected sockets ignore the error.
 */
void bpf2socks_udp_token_notify_unknown(
    struct bpf2socks_udp_state *state,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_udp_client_packet *packet,
    uint64_t now_ms) {
    if (!bpf2socks_sockaddr_is_loopback(&packet->client_addr) ||
        packet->client_addr.ss_family != packet->token_family) {
        return;
    }
    if (now_ms - state->token_notice_window_ms >= 1000U) {
        state->token_notice_window_ms = now_ms;
        state->token_notice_count = 0U;
    }
    if (state->token_notice_count >= BPF2SOCKS_UDP_TOKEN_NOTICES_PER_SECOND) return;
    ++state->token_notice_count;
    size_t quoted_len = packet->payload_len;
    if (quoted_len > UINT16_MAX - 48U) quoted_len = UINT16_MAX - 48U;

    if (packet->client_addr.ss_family == AF_INET) {
        if (state->token_notice4_fd < 0) {
            state->token_notice4_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
            if (state->token_notice4_fd < 0) return;
        }
        const struct sockaddr_in *client = (const struct sockaddr_in *)&packet->client_addr;
        uint8_t message[8U + sizeof(struct iphdr) + sizeof(struct bpf2socks_udp_header)];
        memset(message, 0, sizeof(message));
        message[0] = 3U; /* destination unreachable */
        message[1] = 3U; /* port unreachable */
        struct iphdr *ip = (struct iphdr *)(message + 8U);
        ip->version = 4;
        ip->ihl = sizeof(*ip) / 4U;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->tot_len = htons((uint16_t)(sizeof(*ip) + sizeof(struct bpf2socks_udp_header) + quoted_len));
        ip->saddr = client->sin_addr.s_addr;
        memcpy(&ip->daddr, packet->token_addr, 4U);
        ip->check = htons(bpf2socks_udp_checksum_fold(bpf2socks_udp_checksum_add_bytes(0, ip, sizeof(*ip))));
        struct bpf2socks_udp_header *udp = (struct bpf2socks_udp_header *)(message + 8U + sizeof(*ip));
        udp->source = client->sin_port;
        udp->dest = htons(config->listen_port);
        udp->len = htons((uint16_t)(sizeof(*udp) + quoted_len));
        uint16_t checksum = htons(bpf2socks_udp_checksum_fold(bpf2socks_udp_checksum_add_bytes(0, message, sizeof(message))));
        memcpy(message + 2U, &checksum, sizeof(checksum));
        (void)sendto(state->token_notice4_fd, message, sizeof(message), 0,
            (const struct sockaddr *)client, sizeof(*client));
        return;
    }

    if (state->token_notice6_fd < 0) {
        state->token_notice6_fd = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMPV6);
        if (state->token_notice6_fd < 0) return;
    }
    struct sockaddr_in6 client = *(const struct sockaddr_in6 *)&packet->client_addr;
    uint8_t message[8U + sizeof(struct ipv6hdr) + sizeof(struct bpf2socks_udp_header)];
    memset(message, 0, sizeof(message));
    message[0] = 1U; /* destination unreachable; the kernel fills the checksum */
    message[1] = 4U; /* port unreachable */
    struct ipv6hdr *ip = (struct ipv6hdr *)(message + 8U);
    ip->version = 6;
    ip->payload_len = htons((uint16_t)(sizeof(struct bpf2socks_udp_header) + quoted_len));
    ip->nexthdr = IPPROTO_UDP;
    ip->hop_limit = 64;
    memcpy(&ip->saddr, &client.sin6_addr, 16U);
    memcpy(&ip->daddr, packet->token_addr, 16U);
    struct bpf2socks_udp_header *udp = (struct bpf2socks_udp_header *)(message + 8U + sizeof(*ip));
    udp->source = client.sin6_port;
    udp->dest = htons(config->listen_port);
    udp->len = htons((uint16_t)(sizeof(*udp) + quoted_len));
    client.sin6_port = 0;
    (void)sendto(state->token_notice6_fd, message, sizeof(message), 0,
        (const struct sockaddr *)&client, sizeof(client));
}

/*
 * A local client's socket is gone, so no datagram can carry its tokens any
 * more: drop them instead of leaving them to crowd live flows out of the LRU.
 */
void bpf2socks_udp_token_delete_closed_client(
    const struct bpf2socks_bridge_worker *worker,
    const struct bpf2socks_udp_client_session *session) {
    int family = session->client_addr.ss_family;
    for (const struct bpf2socks_udp_reply_binding *binding = session->bindings;
         binding != NULL;
         binding = binding->next) {
        if (!binding->used || !bpf2socks_udp_binding_has_token(binding)) continue;
        struct bpf2socks_token_key key;
        fill_client_less_udp_token_key(&key, family, binding->token_addr, worker->config->listen_port);
        (void)bpf2socks_bpf_map_delete(worker->config->token_map_fd, &key);
    }
}

int bpf2socks_udp_token_parse_cmsgs(
    struct msghdr *msg,
    const struct bpf2socks_runtime_config *config,
    struct bpf2socks_udp_client_packet *packet) {
    bool has_pktinfo = false;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            const struct in_pktinfo *pktinfo = (const struct in_pktinfo *)CMSG_DATA(cmsg);
            packet->token_family = AF_INET;
            memcpy(packet->token_addr, &pktinfo->ipi_addr, 4);
            has_pktinfo = true;
            continue;
        } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            const struct in6_pktinfo *pktinfo = (const struct in6_pktinfo *)CMSG_DATA(cmsg);
            packet->token_family = AF_INET6;
            memcpy(packet->token_addr, &pktinfo->ipi6_addr, 16);
            has_pktinfo = true;
            continue;
        }

        struct bpf2socks_original_dst original;
        if (bpf2socks_original_dst_from_cmsg(cmsg, config, BPF2SOCKS_PROTO_UDP, &original) == 0 &&
            bpf2socks_original_dst_to_sockaddr(&original, &packet->original_dst) == 0) {
            packet->has_original_dst = true;
        }
    }
    return has_pktinfo ? 0 : -1;
}
