// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "core/config.h"
#include "bpf/policy.h"
#include "bpf2socks.h"
#include "core/json.h"
#include "core/log.h"
#include "core/token.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool env_bool_enabled(const char *key) {
    const char *value = getenv(key);
    return value != NULL && (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 || strcmp(value, "TRUE") == 0);
}

static void init_runtime_config_defaults(struct bpf2socks_runtime_config *config) {
    memset(config, 0, sizeof(*config));
    config->token_map_fd = -1;
    config->reuseport_tcp4_map_fd = -1;
    config->reuseport_udp4_map_fd = -1;
    config->reuseport_tcp6_map_fd = -1;
    config->reuseport_udp6_map_fd = -1;
    config->reuseport_prog_fd = -1;
    (void)bpf2socks_token_prefix_parse4(
        BPF2SOCKS_DEFAULT_TOKEN_IPV4_PREFIX,
        config->token_ipv4_prefix,
        &config->token_ipv4_prefix_bits);
    (void)bpf2socks_token_prefix_parse6(
        BPF2SOCKS_DEFAULT_TOKEN_IPV6_PREFIX,
        config->token_ipv6_prefix,
        &config->token_ipv6_prefix_bits);
    snprintf(config->cgroup_path, sizeof(config->cgroup_path), "%s", BPF2SOCKS_DEFAULT_CGROUP_PATH);
    config->worker_count = 0U;
    config->tcp_buffer_size = BPF2SOCKS_DEFAULT_TCP_BUFFER_SIZE;
    config->max_tcp_sessions = BPF2SOCKS_DEFAULT_MAX_TCP_SESSIONS;
    config->connect_timeout_milliseconds = BPF2SOCKS_DEFAULT_CONNECT_TIMEOUT_MILLISECONDS;
    config->tcp_idle_timeout_milliseconds = BPF2SOCKS_DEFAULT_TCP_IDLE_TIMEOUT_MILLISECONDS;
    config->udp_socket_buffer_size = BPF2SOCKS_DEFAULT_UDP_SOCKET_BUFFER_SIZE;
    config->udp_batch_size = BPF2SOCKS_DEFAULT_UDP_BATCH_SIZE;
    config->max_udp_sessions = BPF2SOCKS_DEFAULT_MAX_UDP_SESSIONS;
    config->max_udp_bindings = BPF2SOCKS_DEFAULT_MAX_UDP_BINDINGS;
    config->udp_idle_timeout_seconds = BPF2SOCKS_DEFAULT_UDP_IDLE_TIMEOUT_SECONDS;
    config->max_udp_pending_bytes = BPF2SOCKS_DEFAULT_MAX_UDP_PENDING_BYTES;
    config->dns_transaction_timeout_milliseconds = BPF2SOCKS_DEFAULT_DNS_TRANSACTION_TIMEOUT_MILLISECONDS;
}

static void init_policy_config_defaults(struct bpf2socks_policy_config *policy) {
    memset(policy, 0, sizeof(*policy));
    policy->mode = BPF2SOCKS_MODE_GLOBAL;
    policy->self_bypass_gid_enabled = true;
    policy->self_bypass_gid = (uint32_t)getegid();
}

static uint32_t auto_worker_count(void) {
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count >= 8L) return 4U;
    return BPF2SOCKS_DEFAULT_WORKER_COUNT;
}

static void normalize_runtime_tunables(struct bpf2socks_runtime_config *config) {
    if (config->worker_count == 0U) config->worker_count = auto_worker_count();
    if (config->worker_count > BPF2SOCKS_MAX_WORKER_COUNT) config->worker_count = BPF2SOCKS_MAX_WORKER_COUNT;
    if (config->max_tcp_sessions == 0U) config->max_tcp_sessions = BPF2SOCKS_DEFAULT_MAX_TCP_SESSIONS;
    if (config->max_tcp_sessions > BPF2SOCKS_MAX_TCP_SESSIONS) {
        config->max_tcp_sessions = BPF2SOCKS_MAX_TCP_SESSIONS;
    }
    if (config->connect_timeout_milliseconds == 0U) {
        config->connect_timeout_milliseconds = BPF2SOCKS_DEFAULT_CONNECT_TIMEOUT_MILLISECONDS;
    }
    if (config->connect_timeout_milliseconds < BPF2SOCKS_MIN_CONNECT_TIMEOUT_MILLISECONDS) {
        config->connect_timeout_milliseconds = BPF2SOCKS_MIN_CONNECT_TIMEOUT_MILLISECONDS;
    }
    if (config->connect_timeout_milliseconds > BPF2SOCKS_MAX_CONNECT_TIMEOUT_MILLISECONDS) {
        config->connect_timeout_milliseconds = BPF2SOCKS_MAX_CONNECT_TIMEOUT_MILLISECONDS;
    }
    if (config->tcp_idle_timeout_milliseconds != 0U &&
        config->tcp_idle_timeout_milliseconds < BPF2SOCKS_MIN_TCP_IDLE_TIMEOUT_MILLISECONDS) {
        config->tcp_idle_timeout_milliseconds = BPF2SOCKS_MIN_TCP_IDLE_TIMEOUT_MILLISECONDS;
    }
    if (config->tcp_idle_timeout_milliseconds > BPF2SOCKS_MAX_TCP_IDLE_TIMEOUT_MILLISECONDS) {
        config->tcp_idle_timeout_milliseconds = BPF2SOCKS_MAX_TCP_IDLE_TIMEOUT_MILLISECONDS;
    }
    if (config->udp_socket_buffer_size == 0U) {
        config->udp_socket_buffer_size = BPF2SOCKS_DEFAULT_UDP_SOCKET_BUFFER_SIZE;
    }
    if (config->udp_batch_size == 0U) config->udp_batch_size = BPF2SOCKS_DEFAULT_UDP_BATCH_SIZE;
    if (config->max_udp_sessions == 0U) config->max_udp_sessions = BPF2SOCKS_DEFAULT_MAX_UDP_SESSIONS;
    if (config->max_udp_bindings == 0U) config->max_udp_bindings = BPF2SOCKS_DEFAULT_MAX_UDP_BINDINGS;
    if (config->max_udp_bindings < config->max_udp_sessions) {
        config->max_udp_bindings = config->max_udp_sessions;
    }
    if (config->udp_idle_timeout_seconds == 0U) {
        config->udp_idle_timeout_seconds = BPF2SOCKS_DEFAULT_UDP_IDLE_TIMEOUT_SECONDS;
    }
    if (config->max_udp_pending_bytes == 0U) {
        config->max_udp_pending_bytes = BPF2SOCKS_DEFAULT_MAX_UDP_PENDING_BYTES;
    }
    if (config->max_udp_pending_bytes < BPF2SOCKS_MIN_UDP_PENDING_BYTES) {
        config->max_udp_pending_bytes = BPF2SOCKS_MIN_UDP_PENDING_BYTES;
    }
    if (config->max_udp_pending_bytes > BPF2SOCKS_MAX_UDP_PENDING_BYTES) {
        config->max_udp_pending_bytes = BPF2SOCKS_MAX_UDP_PENDING_BYTES;
    }
    if (config->dns_transaction_timeout_milliseconds == 0U) {
        config->dns_transaction_timeout_milliseconds = BPF2SOCKS_DEFAULT_DNS_TRANSACTION_TIMEOUT_MILLISECONDS;
    }
    if (config->dns_transaction_timeout_milliseconds < BPF2SOCKS_MIN_DNS_TRANSACTION_TIMEOUT_MILLISECONDS) {
        config->dns_transaction_timeout_milliseconds = BPF2SOCKS_MIN_DNS_TRANSACTION_TIMEOUT_MILLISECONDS;
    }
    if (config->dns_transaction_timeout_milliseconds > BPF2SOCKS_MAX_DNS_TRANSACTION_TIMEOUT_MILLISECONDS) {
        config->dns_transaction_timeout_milliseconds = BPF2SOCKS_MAX_DNS_TRANSACTION_TIMEOUT_MILLISECONDS;
    }
    if (config->max_tcp_sessions < config->worker_count) config->worker_count = config->max_tcp_sessions;
    if (config->max_udp_sessions < config->worker_count) config->worker_count = config->max_udp_sessions;
    if (config->max_udp_bindings < config->worker_count) config->worker_count = config->max_udp_bindings;
}

static bool check_field(bool valid, const char *key) {
    if (!valid) bpf2socks_log("invalid config field: %s", key);
    return valid;
}

/* An absent optional field keeps its default; a malformed or out-of-range one fails the config. */
static bool read_uint_field(const char *json, const char *key, uint32_t max_value, uint32_t *value) {
    return check_field(bpf2socks_json_uint_field(json, key, max_value, value), key);
}

/* A value that does not fit is rejected rather than truncated into another path or address. */
static bool read_string_field(const char *json, const char *key, bool required, char *out, size_t out_size) {
    if (!required && !bpf2socks_json_has_key(json, key)) return true;
    return check_field(bpf2socks_json_string(json, key, out, out_size), key);
}

void bpf2socks_config_defaults(
    struct bpf2socks_runtime_config *config,
    struct bpf2socks_policy_config *policy) {
    init_runtime_config_defaults(config);
    init_policy_config_defaults(policy);
}

int bpf2socks_config_load(
    const char *path,
    bool dns_enhancement,
    struct bpf2socks_runtime_config *config,
    struct bpf2socks_policy_config *policy) {
    bpf2socks_config_defaults(config, policy);
    char *json = bpf2socks_json_read_file(path);
    if (json == NULL) {
        bpf2socks_log("failed to read config: %s", path);
        return -1;
    }

    bool ok = true;
    ok = read_string_field(json, "socksHost", true, config->socks_host, sizeof(config->socks_host)) && ok;
    uint32_t socks_port = 0U;
    ok = read_uint_field(json, "socksPort", UINT16_MAX, &socks_port) && ok;
    config->socks_port = (uint16_t)socks_port;
    ok = read_string_field(json, "bridgeListenAddress", true, config->listen_host, sizeof(config->listen_host)) && ok;
    uint32_t listen_port = 0U;
    ok = read_uint_field(json, "bridgePort", UINT16_MAX, &listen_port) && ok;
    config->listen_port = (uint16_t)listen_port;
    ok = read_string_field(
        json, "pinnedObjectDir", true, config->pinned_object_dir, sizeof(config->pinned_object_dir)) && ok;
    ok = read_string_field(json, "cgroupPath", false, config->cgroup_path, sizeof(config->cgroup_path)) && ok;
    if (config->cgroup_path[0] == '\0') {
        snprintf(config->cgroup_path, sizeof(config->cgroup_path), "%s", BPF2SOCKS_DEFAULT_CGROUP_PATH);
    }
    config->enable_ipv6 = bpf2socks_json_bool(json, "enableIpv6", false);
    config->enable_dns_hijack = bpf2socks_json_bool(json, "enableDnsHijack", false);
    config->debug_stats =
        bpf2socks_json_bool(json, "debugStats", false) || env_bool_enabled("BPF2SOCKS_DEBUG_STATS");
    char token_ipv4_prefix[INET_ADDRSTRLEN + 4U] = "";
    ok = read_string_field(json, "tokenIpv4Prefix", false, token_ipv4_prefix, sizeof(token_ipv4_prefix)) && ok;
    if (bpf2socks_json_has_key(json, "tokenIpv4Prefix") &&
        bpf2socks_token_prefix_parse4(
            token_ipv4_prefix,
            config->token_ipv4_prefix,
            &config->token_ipv4_prefix_bits) < 0) {
        bpf2socks_log("invalid IPv4 token prefix: %s", token_ipv4_prefix);
        ok = false;
    }
    char token_ipv6_prefix[128] = "";
    ok = read_string_field(json, "tokenIpv6Prefix", false, token_ipv6_prefix, sizeof(token_ipv6_prefix)) && ok;
    if (bpf2socks_json_has_key(json, "tokenIpv6Prefix") &&
        bpf2socks_token_prefix_parse6(
            token_ipv6_prefix,
            config->token_ipv6_prefix,
            &config->token_ipv6_prefix_bits) < 0) {
        bpf2socks_log("invalid IPv6 token prefix: %s", token_ipv6_prefix);
        ok = false;
    }
    ok = read_uint_field(json, "workerCount", UINT32_MAX, &config->worker_count) && ok;
    ok = read_uint_field(json, "tcpBufferSize", UINT32_MAX, &config->tcp_buffer_size) && ok;
    ok = read_uint_field(json, "maxTcpSessions", UINT32_MAX, &config->max_tcp_sessions) && ok;
    ok = read_uint_field(
        json, "connectTimeoutMilliseconds", UINT32_MAX, &config->connect_timeout_milliseconds) && ok;
    ok = read_uint_field(
        json, "tcpIdleTimeoutMilliseconds", UINT32_MAX, &config->tcp_idle_timeout_milliseconds) && ok;
    ok = read_uint_field(json, "udpSocketBufferSize", UINT32_MAX, &config->udp_socket_buffer_size) && ok;
    ok = read_uint_field(json, "udpBatchSize", UINT32_MAX, &config->udp_batch_size) && ok;
    ok = read_uint_field(json, "maxUdpSessions", UINT32_MAX, &config->max_udp_sessions) && ok;
    ok = read_uint_field(json, "maxUdpBindings", UINT32_MAX, &config->max_udp_bindings) && ok;
    ok = read_uint_field(json, "udpIdleTimeoutSeconds", UINT32_MAX, &config->udp_idle_timeout_seconds) && ok;
    ok = read_uint_field(json, "maxUdpPendingBytes", UINT32_MAX, &config->max_udp_pending_bytes) && ok;
    ok = read_uint_field(
        json,
        "dnsTransactionTimeoutMilliseconds",
        UINT32_MAX,
        &config->dns_transaction_timeout_milliseconds) && ok;
    normalize_runtime_tunables(config);

    const char *policy_object = bpf2socks_json_object(json, "policy");
    const char *policy_json = policy_object != NULL ? policy_object : json;
    ok = read_uint_field(policy_json, "mode", BPF2SOCKS_MODE_GLOBAL, &policy->mode) && ok;
    policy->bypass_direct_cidrs = bpf2socks_json_bool(policy_json, "bypassDirectCidrs", false);
    policy->enable_ipv6 = config->enable_ipv6;
    policy->enable_dns_hijack = config->enable_dns_hijack;
    policy->enable_dns_enhancement = dns_enhancement;
    if (dns_enhancement && !config->enable_dns_hijack) {
        bpf2socks_log("DNS enhancement requires DNS interception");
        ok = false;
    }
    ok = read_string_field(
        policy_json,
        "directCidrPathV4",
        false,
        policy->direct_cidr_path_v4,
        sizeof(policy->direct_cidr_path_v4)) && ok;
    ok = read_string_field(
        policy_json,
        "directCidrPathV6",
        false,
        policy->direct_cidr_path_v6,
        sizeof(policy->direct_cidr_path_v6)) && ok;
    ok = check_field(
        bpf2socks_json_uint_array(
            policy_json,
            "uids",
            policy->uids,
            &policy->uid_count,
            BPF2SOCKS_MAX_UIDS),
        "uids") && ok;
    ok = check_field(
        bpf2socks_json_uint_array(
            policy_json,
            "bypassUids",
            policy->bypass_uids,
            &policy->bypass_uid_count,
            BPF2SOCKS_MAX_UIDS),
        "bypassUids") && ok;
    /* Hotspot TC filters are attached by the supervisor; only their presence matters here. */
    char hotspot_interface_prefixes[BPF2SOCKS_MAX_INTERFACES][BPF2SOCKS_MAX_INTERFACE_NAME_LEN];
    ok = check_field(
        bpf2socks_json_string_array(
            json,
            "hotspotInterfacePrefixes",
            (char *)hotspot_interface_prefixes,
            BPF2SOCKS_MAX_INTERFACE_NAME_LEN,
            &policy->hotspot_interface_prefix_count,
            BPF2SOCKS_MAX_INTERFACES),
        "hotspotInterfacePrefixes") && ok;
    ok = check_field(
        bpf2socks_json_string_array(
            json,
            "ignoredInterfaces",
            (char *)policy->ignored_interfaces,
            BPF2SOCKS_MAX_INTERFACE_NAME_LEN,
            &policy->ignored_interface_count,
            BPF2SOCKS_MAX_INTERFACES),
        "ignoredInterfaces") && ok;
    for (size_t index = 0U; index < policy->ignored_interface_count; ++index) {
        if (!bpf2socks_interface_selector_valid(policy->ignored_interfaces[index])) {
            bpf2socks_log("invalid ignored interface selector: %s",
                policy->ignored_interfaces[index]);
            ok = false;
        }
    }
    ok = check_field(
        bpf2socks_json_string_array(
            json,
            "proxyPrivateCidrsV4",
            (char *)policy->proxy_private_cidrs_v4,
            BPF2SOCKS_MAX_CIDR_TEXT_LEN,
            &policy->proxy_private_cidr_v4_count,
            BPF2SOCKS_MAX_POLICY_CIDRS),
        "proxyPrivateCidrsV4") && ok;
    ok = check_field(
        bpf2socks_json_string_array(
            json,
            "bypassPrivateCidrsV4",
            (char *)policy->bypass_private_cidrs_v4,
            BPF2SOCKS_MAX_CIDR_TEXT_LEN,
            &policy->bypass_private_cidr_v4_count,
            BPF2SOCKS_MAX_POLICY_CIDRS),
        "bypassPrivateCidrsV4") && ok;
    ok = check_field(
        bpf2socks_json_string_array(
            json,
            "proxyPrivateCidrsV6",
            (char *)policy->proxy_private_cidrs_v6,
            BPF2SOCKS_MAX_CIDR_TEXT_LEN,
            &policy->proxy_private_cidr_v6_count,
            BPF2SOCKS_MAX_POLICY_CIDRS),
        "proxyPrivateCidrsV6") && ok;
    ok = check_field(
        bpf2socks_json_string_array(
            json,
            "bypassPrivateCidrsV6",
            (char *)policy->bypass_private_cidrs_v6,
            BPF2SOCKS_MAX_CIDR_TEXT_LEN,
            &policy->bypass_private_cidr_v6_count,
            BPF2SOCKS_MAX_POLICY_CIDRS),
        "bypassPrivateCidrsV6") && ok;

    free(json);
    if (!ok || config->socks_port == 0U || config->listen_port == 0U) {
        bpf2socks_log("invalid config: %s", path);
        return -1;
    }
    return 0;
}
