// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BRIDGE_STATS_H
#define BPF2SOCKS_BRIDGE_STATS_H

#include <stdint.h>

/*
 * Every debug counter, in --stats JSON order: TCP(...) counters belong to the
 * TCP threads, UDP(...) to the UDP threads, and PEAK(...) is the shared UDP
 * pending budget's high-water mark, taken at aggregation time.
 */
#define BPF2SOCKS_BRIDGE_STATS(TCP, UDP, PEAK) \
    TCP(tcp_accepts, "tcpAccepts") \
    TCP(tcp_connect_failures, "tcpConnectFailures") \
    TCP(tcp_drops_capacity, "tcpDropsCapacity") \
    TCP(tcp_connect_timeouts, "tcpConnectTimeouts") \
    TCP(tcp_idle_timeouts, "tcpIdleTimeouts") \
    TCP(tcp_fd_exhaustions, "tcpFdExhaustions") \
    TCP(tcp_token_delete_failures, "tcpTokenDeleteFailures") \
    TCP(tcp_bytes_client_to_upstream, "tcpBytesClientToUpstream") \
    TCP(tcp_bytes_upstream_to_client, "tcpBytesUpstreamToClient") \
    UDP(udp_packets_from_client, "udpPacketsFromClient") \
    UDP(udp_packets_to_upstream, "udpPacketsToUpstream") \
    UDP(udp_packets_from_upstream, "udpPacketsFromUpstream") \
    UDP(udp_packets_to_client, "udpPacketsToClient") \
    UDP(udp_token_misses, "udpTokenMisses") \
    UDP(udp_session_hits, "udpSessionHits") \
    UDP(udp_session_misses, "udpSessionMisses") \
    UDP(udp_session_evictions, "udpSessionEvictions") \
    UDP(udp_associate_creates, "udpAssociateCreates") \
    UDP(udp_associate_reuses, "udpAssociateReuses") \
    UDP(udp_reply_binding_creates, "udpReplyBindingCreates") \
    UDP(udp_reply_binding_hits, "udpReplyBindingHits") \
    UDP(udp_fullcone_binding_creates, "udpFullconeBindingCreates") \
    UDP(udp_binding_evictions, "udpBindingEvictions") \
    UDP(udp_drops_malformed_socks5, "udpDropsMalformedSocks5") \
    UDP(udp_drops_oversized, "udpDropsOversized") \
    UDP(udp_drops_pending_budget, "udpDropsPendingBudget") \
    PEAK(udp_pending_peak_bytes, "udpPendingPeakBytes") \
    UDP(udp_send_errors, "udpSendErrors") \
    UDP(dns_valid_responses, "dnsValidResponses") \
    UDP(dns_transaction_timeouts, "dnsTransactionTimeouts") \
    UDP(dns_channel_timeout_rebuilds, "dnsChannelTimeoutRebuilds") \
    UDP(udp_token_lookup_full_attempts, "udpTokenLookupFullAttempts") \
    UDP(udp_token_lookup_full_hits, "udpTokenLookupFullHits") \
    UDP(udp_token_lookup_zero_attempts, "udpTokenLookupZeroAttempts") \
    UDP(udp_token_lookup_zero_hits, "udpTokenLookupZeroHits") \
    UDP(udp_token_lookup_fallbacks, "udpTokenLookupFallbacks") \
    UDP(udp_copy_sends, "udpCopySends") \
    UDP(udp_binding_hash_lookups, "udpBindingHashLookups") \
    UDP(udp_binding_hash_collision_steps, "udpBindingHashCollisionSteps") \
    UDP(dns_free_stack_allocations, "dnsFreeStackAllocations") \
    UDP(dns_full_table_evictions, "dnsFullTableEvictions") \
    UDP(udp_drops_send_busy, "udpDropsSendBusy") \
    UDP(udp_associate_timeouts, "udpAssociateTimeouts") \
    UDP(udp_closed_client_releases, "udpClosedClientReleases") \
    UDP(udp_relay_port_collisions, "udpRelayPortCollisions") \
    UDP(udp_release_events, "udpReleaseEvents") \
    UDP(udp_release_confirm_queries, "udpReleaseConfirmQueries") \
    UDP(udp_release_events_lost, "udpReleaseEventsLost")

#define BPF2SOCKS_BRIDGE_STATS_FIELD(name, json) uint64_t name;
struct bpf2socks_bridge_stats {
    BPF2SOCKS_BRIDGE_STATS(BPF2SOCKS_BRIDGE_STATS_FIELD, BPF2SOCKS_BRIDGE_STATS_FIELD, BPF2SOCKS_BRIDGE_STATS_FIELD)
};
#undef BPF2SOCKS_BRIDGE_STATS_FIELD

/* Reads the snapshot a running instance publishes next to its PID file. */
int bpf2socks_bridge_stats_read(const char *pid_path, struct bpf2socks_bridge_stats *out);
/* Writes the stats as one JSON object line to stdout. */
void bpf2socks_bridge_stats_print_json(const struct bpf2socks_bridge_stats *stats);

#endif
