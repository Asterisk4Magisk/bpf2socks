// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf2socks.h"
#include "json_util.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define BPF2SOCKS_FD_RUNTIME_RESERVE 32ULL
#define BPF2SOCKS_FD_SAFETY_MARGIN 256ULL
#define BPF2SOCKS_FD_PER_WORKER_TCP 3ULL
#define BPF2SOCKS_FD_PER_WORKER_TCP_IPV6 1ULL
#define BPF2SOCKS_FD_PER_WORKER_UDP 7ULL
#define BPF2SOCKS_FD_PER_WORKER_UDP_IPV6 2ULL

static void on_signal(int signo) {
    (void)signo;
    bpf2socks_request_stop();
}

static void install_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    action.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &action, NULL);
}

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
    (void)bpf2socks_parse_token_ipv4_prefix(
        BPF2SOCKS_DEFAULT_TOKEN_IPV4_PREFIX,
        config->token_ipv4_prefix,
        &config->token_ipv4_prefix_bits);
    (void)bpf2socks_parse_token_ipv6_prefix(
        BPF2SOCKS_DEFAULT_TOKEN_IPV6_PREFIX,
        config->token_ipv6_prefix,
        &config->token_ipv6_prefix_bits);
    snprintf(config->cgroup_path, sizeof(config->cgroup_path), "%s", BPF2SOCKS_DEFAULT_CGROUP_PATH);
    config->worker_count = 0U;
    config->tcp_buffer_size = BPF2SOCKS_DEFAULT_TCP_BUFFER_SIZE;
    config->max_tcp_sessions = BPF2SOCKS_DEFAULT_MAX_TCP_SESSIONS;
    config->tcp_connect_timeout_milliseconds = BPF2SOCKS_DEFAULT_TCP_CONNECT_TIMEOUT_MILLISECONDS;
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
    if (config->tcp_buffer_size == 0U) config->tcp_buffer_size = BPF2SOCKS_DEFAULT_TCP_BUFFER_SIZE;
    if (config->max_tcp_sessions == 0U) config->max_tcp_sessions = BPF2SOCKS_DEFAULT_MAX_TCP_SESSIONS;
    if (config->max_tcp_sessions > BPF2SOCKS_MAX_TCP_SESSIONS) {
        config->max_tcp_sessions = BPF2SOCKS_MAX_TCP_SESSIONS;
    }
    if (config->tcp_connect_timeout_milliseconds == 0U) {
        config->tcp_connect_timeout_milliseconds = BPF2SOCKS_DEFAULT_TCP_CONNECT_TIMEOUT_MILLISECONDS;
    }
    if (config->tcp_connect_timeout_milliseconds < BPF2SOCKS_MIN_TCP_CONNECT_TIMEOUT_MILLISECONDS) {
        config->tcp_connect_timeout_milliseconds = BPF2SOCKS_MIN_TCP_CONNECT_TIMEOUT_MILLISECONDS;
    }
    if (config->tcp_connect_timeout_milliseconds > BPF2SOCKS_MAX_TCP_CONNECT_TIMEOUT_MILLISECONDS) {
        config->tcp_connect_timeout_milliseconds = BPF2SOCKS_MAX_TCP_CONNECT_TIMEOUT_MILLISECONDS;
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

static int load_runtime_config(
    const char *path,
    struct bpf2socks_runtime_config *config,
    struct bpf2socks_policy_config *policy) {
    init_runtime_config_defaults(config);
    init_policy_config_defaults(policy);
    char *json = bpf2socks_json_read_file(path);
    if (json == NULL) {
        fprintf(stderr, "failed to read config: %s\n", path);
        return -1;
    }

    bool ok = true;
    ok = bpf2socks_json_string(json, "socksHost", config->socks_host, sizeof(config->socks_host)) && ok;
    config->socks_port = (uint16_t)bpf2socks_json_uint(json, "socksPort", 0U);
    ok = bpf2socks_json_string(json, "bridgeListenAddress", config->listen_host, sizeof(config->listen_host)) && ok;
    config->listen_port = (uint16_t)bpf2socks_json_uint(json, "bridgePort", 0U);
    ok = bpf2socks_json_string(json, "pinnedObjectDir", config->pinned_object_dir, sizeof(config->pinned_object_dir)) && ok;
    if (!bpf2socks_json_string(json, "cgroupPath", config->cgroup_path, sizeof(config->cgroup_path))) {
        snprintf(config->cgroup_path, sizeof(config->cgroup_path), "%s", BPF2SOCKS_DEFAULT_CGROUP_PATH);
    }
    config->enable_ipv6 = bpf2socks_json_bool(json, "enableIpv6", false);
    config->enable_dns_hijack = bpf2socks_json_bool(json, "enableDnsHijack", false);
    config->debug_stats =
        bpf2socks_json_bool(json, "debugStats", false) || env_bool_enabled("BPF2SOCKS_DEBUG_STATS");
    char token_ipv4_prefix[INET_ADDRSTRLEN + 4U];
    if (bpf2socks_json_string(json, "tokenIpv4Prefix", token_ipv4_prefix, sizeof(token_ipv4_prefix)) &&
        bpf2socks_parse_token_ipv4_prefix(
            token_ipv4_prefix,
            config->token_ipv4_prefix,
            &config->token_ipv4_prefix_bits) < 0) {
        fprintf(stderr, "invalid bpf2socks IPv4 token prefix: %s\n", token_ipv4_prefix);
        ok = false;
    }
    char token_ipv6_prefix[128];
    if (bpf2socks_json_string(json, "tokenIpv6Prefix", token_ipv6_prefix, sizeof(token_ipv6_prefix)) &&
        bpf2socks_parse_token_ipv6_prefix(
            token_ipv6_prefix,
            config->token_ipv6_prefix,
            &config->token_ipv6_prefix_bits) < 0) {
        fprintf(stderr, "invalid bpf2socks IPv6 token prefix: %s\n", token_ipv6_prefix);
        ok = false;
    }
    config->worker_count = bpf2socks_json_uint(json, "workerCount", config->worker_count);
    config->tcp_buffer_size = bpf2socks_json_uint(json, "tcpBufferSize", config->tcp_buffer_size);
    config->max_tcp_sessions = bpf2socks_json_uint(json, "maxTcpSessions", config->max_tcp_sessions);
    config->tcp_connect_timeout_milliseconds = bpf2socks_json_uint(
        json,
        "tcpConnectTimeoutMilliseconds",
        config->tcp_connect_timeout_milliseconds);
    config->tcp_idle_timeout_milliseconds = bpf2socks_json_uint(
        json,
        "tcpIdleTimeoutMilliseconds",
        config->tcp_idle_timeout_milliseconds);
    config->udp_socket_buffer_size = bpf2socks_json_uint(
        json,
        "udpSocketBufferSize",
        config->udp_socket_buffer_size);
    config->udp_batch_size = bpf2socks_json_uint(json, "udpBatchSize", config->udp_batch_size);
    config->max_udp_sessions = bpf2socks_json_uint(json, "maxUdpSessions", config->max_udp_sessions);
    config->max_udp_bindings = bpf2socks_json_uint(json, "maxUdpBindings", config->max_udp_bindings);
    config->udp_idle_timeout_seconds = bpf2socks_json_uint(
        json,
        "udpIdleTimeoutSeconds",
        config->udp_idle_timeout_seconds);
    config->max_udp_pending_bytes = bpf2socks_json_uint(
        json,
        "maxUdpPendingBytes",
        config->max_udp_pending_bytes);
    config->dns_transaction_timeout_milliseconds = bpf2socks_json_uint(
        json,
        "dnsTransactionTimeoutMilliseconds",
        config->dns_transaction_timeout_milliseconds);
    normalize_runtime_tunables(config);

    const char *policy_object = bpf2socks_json_object(json, "policy");
    const char *policy_json = policy_object != NULL ? policy_object : json;
    policy->mode = bpf2socks_json_uint(policy_json, "mode", BPF2SOCKS_MODE_GLOBAL);
    policy->bypass_direct_cidrs = bpf2socks_json_bool(policy_json, "bypassDirectCidrs", false);
    policy->enable_ipv6 = config->enable_ipv6;
    policy->enable_dns_hijack = config->enable_dns_hijack;
    (void)bpf2socks_json_string(
        policy_json,
        "directCidrPathV4",
        policy->direct_cidr_path_v4,
        sizeof(policy->direct_cidr_path_v4));
    (void)bpf2socks_json_string(
        policy_json,
        "directCidrPathV6",
        policy->direct_cidr_path_v6,
        sizeof(policy->direct_cidr_path_v6));
    bpf2socks_json_uint_array(
        policy_json,
        "uids",
        policy->uids,
        &policy->uid_count,
        BPF2SOCKS_MAX_UIDS);
    bpf2socks_json_uint_array(
        policy_json,
        "bypassUids",
        policy->bypass_uids,
        &policy->bypass_uid_count,
        BPF2SOCKS_MAX_UIDS);
    (void)bpf2socks_json_string_array(
        json,
        "hotspotInterfacePrefixes",
        (char *)policy->hotspot_interface_prefixes,
        BPF2SOCKS_MAX_INTERFACE_NAME_LEN,
        &policy->hotspot_interface_prefix_count,
        BPF2SOCKS_MAX_INTERFACES);
    if (!bpf2socks_json_string_array(
            json,
            "ignoredInterfaces",
            (char *)policy->ignored_interfaces,
            BPF2SOCKS_MAX_INTERFACE_NAME_LEN,
            &policy->ignored_interface_count,
            BPF2SOCKS_MAX_INTERFACES)) {
        ok = false;
    }
    for (size_t index = 0U; index < policy->ignored_interface_count; ++index) {
        if (!bpf2socks_interface_selector_valid(policy->ignored_interfaces[index])) {
            fprintf(
                stderr,
                "invalid bpf2socks ignored interface selector: %s\n",
                policy->ignored_interfaces[index]);
            ok = false;
        }
    }
    (void)bpf2socks_json_string_array(
        json,
        "proxyPrivateCidrsV4",
        (char *)policy->proxy_private_cidrs_v4,
        BPF2SOCKS_MAX_CIDR_TEXT_LEN,
        &policy->proxy_private_cidr_v4_count,
        BPF2SOCKS_MAX_POLICY_CIDRS);
    (void)bpf2socks_json_string_array(
        json,
        "bypassPrivateCidrsV4",
        (char *)policy->bypass_private_cidrs_v4,
        BPF2SOCKS_MAX_CIDR_TEXT_LEN,
        &policy->bypass_private_cidr_v4_count,
        BPF2SOCKS_MAX_POLICY_CIDRS);
    (void)bpf2socks_json_string_array(
        json,
        "proxyPrivateCidrsV6",
        (char *)policy->proxy_private_cidrs_v6,
        BPF2SOCKS_MAX_CIDR_TEXT_LEN,
        &policy->proxy_private_cidr_v6_count,
        BPF2SOCKS_MAX_POLICY_CIDRS);
    (void)bpf2socks_json_string_array(
        json,
        "bypassPrivateCidrsV6",
        (char *)policy->bypass_private_cidrs_v6,
        BPF2SOCKS_MAX_CIDR_TEXT_LEN,
        &policy->bypass_private_cidr_v6_count,
        BPF2SOCKS_MAX_POLICY_CIDRS);

    free(json);
    if (!ok || config->socks_port == 0U || config->listen_port == 0U) {
        fprintf(stderr, "invalid bpf2socks config: %s\n", path);
        return -1;
    }
    return 0;
}

static const char *arg_value(int argc, char **argv, const char *name) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return NULL;
}

static const char *config_path_arg(int argc, char **argv) {
    return arg_value(argc, argv, "--config");
}

static const char *pid_path_arg(int argc, char **argv) {
    return arg_value(argc, argv, "--pid");
}

static void print_probe_json(
    bool supported,
    const char *message,
    bool splice_supported,
    bool advanced_socket_supported,
    bool bpf_supported,
    bool hotspot_policy) {
    printf("{\"supported\":%s,\"message\":", supported ? "true" : "false");
    bpf2socks_json_print_string(message);
    if (splice_supported) {
        printf(
            ",\"capabilities\":{\"splice\":true,"
            "\"advancedSockets\":%s,"
            "\"bpf\":%s,"
            "\"reuseport\":%s,"
            "\"tcRedirect\":%s,"
            "\"hotspotPolicy\":%s}}\n",
            advanced_socket_supported ? "true" : "false",
            bpf_supported ? "true" : "false",
            (hotspot_policy && bpf_supported && advanced_socket_supported) ? "true" : "false",
            (hotspot_policy && bpf_supported && advanced_socket_supported) ? "true" : "false",
            hotspot_policy ? "true" : "false");
    } else {
        printf(
            ",\"capabilities\":{\"splice\":false,"
            "\"advancedSockets\":%s,"
            "\"bpf\":%s,"
            "\"reuseport\":false,"
            "\"tcRedirect\":false,"
            "\"hotspotPolicy\":%s}}\n",
            advanced_socket_supported ? "true" : "false",
            bpf_supported ? "true" : "false",
            hotspot_policy ? "true" : "false");
    }
}

static int probe_with_config(const char *path) {
    struct bpf2socks_runtime_config config;
    struct bpf2socks_policy_config policy;
    char message[256];
    if (path != NULL) {
        if (load_runtime_config(path, &config, &policy) < 0) {
            print_probe_json(false, "invalid bpf2socks config", false, false, false, false);
            return 1;
        }
    } else {
        init_runtime_config_defaults(&config);
        init_policy_config_defaults(&policy);
        config.listen_port = 65532U;
    }

    bool hotspot_policy = policy.hotspot_interface_prefix_count > 0U;
    if (bpf2socks_splice_probe(message, sizeof(message)) < 0) {
        print_probe_json(false, message, false, false, false, hotspot_policy);
        return 1;
    }
    if (bpf2socks_advanced_socket_probe(message, sizeof(message)) < 0) {
        print_probe_json(false, message, true, false, false, hotspot_policy);
        return 1;
    }
    if (bpf2socks_raise_memlock_limit() < 0) {
        snprintf(message, sizeof(message), "failed to raise memlock limit: errno=%d", errno);
        print_probe_json(false, message, true, true, false, hotspot_policy);
        return 1;
    }
    if (bpf2socks_bpf_probe(&config, &policy, message, sizeof(message)) == 0) {
        print_probe_json(true, "ok", true, true, true, hotspot_policy);
        return 0;
    }
    print_probe_json(false, message, true, true, false, hotspot_policy);
    return 1;
}

static void cleanup_fixed_bpf_pin(
    const struct bpf2socks_runtime_config *config,
    const char *name) {
    char path[BPF2SOCKS_MAX_PATH_LEN];
    int written = snprintf(path, sizeof(path), "%s/%s", config->pinned_object_dir, name);
    if (written >= 0 && (size_t)written < sizeof(path)) (void)unlink(path);
}

static void cleanup_fixed_bpf_pins(const struct bpf2socks_runtime_config *config) {
    if (config == NULL) return;
    cleanup_fixed_bpf_pin(config, "tc_ingress");
    cleanup_fixed_bpf_pin(config, "tc_egress");
    cleanup_fixed_bpf_pin(config, "local_addr_v4");
    cleanup_fixed_bpf_pin(config, "local_addr_v6");
}

static int current_open_fd_count(uint64_t *out_count) {
    if (out_count == NULL) {
        errno = EINVAL;
        return -1;
    }
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) return -1;
    uint64_t count = 0U;
    for (struct dirent *entry = readdir(directory); entry != NULL; entry = readdir(directory)) {
        if (entry->d_name[0] == '.') continue;
        ++count;
    }
    int close_result = closedir(directory);
    if (close_result != 0) return -1;
    *out_count = count;
    return 0;
}

static uint64_t static_fd_reserve(const struct bpf2socks_runtime_config *config, uint32_t worker_count) {
    uint64_t per_worker = BPF2SOCKS_FD_PER_WORKER_TCP + BPF2SOCKS_FD_PER_WORKER_UDP;
    if (config->enable_ipv6) per_worker += BPF2SOCKS_FD_PER_WORKER_TCP_IPV6;
    if (config->enable_ipv6) per_worker += BPF2SOCKS_FD_PER_WORKER_UDP_IPV6;
    return BPF2SOCKS_FD_RUNTIME_RESERVE + BPF2SOCKS_FD_SAFETY_MARGIN + per_worker * worker_count;
}

static int apply_nofile_session_capacity(struct bpf2socks_runtime_config *config) {
    if (config == NULL) {
        errno = EINVAL;
        return -1;
    }
    uint64_t nofile_limit = 0U;
    uint64_t open_fds = 0U;
    if (bpf2socks_nofile_soft_limit(&nofile_limit) < 0 || current_open_fd_count(&open_fds) < 0) {
        return -1;
    }
    struct bpf2socks_session_capacity requested = {
        .worker_count = config->worker_count,
        .max_tcp_sessions = config->max_tcp_sessions,
        .max_udp_sessions = config->max_udp_sessions,
        .max_udp_bindings = config->max_udp_bindings,
    };
    for (uint32_t worker_count = requested.worker_count; worker_count > 0U; --worker_count) {
        struct bpf2socks_session_capacity effective = requested;
        effective.worker_count = worker_count;
        uint64_t reserve_fds = open_fds + static_fd_reserve(config, worker_count);
        if (bpf2socks_fit_session_capacity(
                nofile_limit,
                reserve_fds,
                &effective) != 0) {
            continue;
        }
        config->worker_count = effective.worker_count;
        config->max_tcp_sessions = effective.max_tcp_sessions;
        config->max_udp_sessions = effective.max_udp_sessions;
        config->max_udp_bindings = effective.max_udp_bindings;
        fprintf(stderr,
            "bpf2socks capacity: nofile=%" PRIu64 " open=%" PRIu64 " reserve=%" PRIu64
            " workers=%u tcp=%u udp=%u bindings=%u\n",
            nofile_limit,
            open_fds,
            reserve_fds,
            config->worker_count,
            config->max_tcp_sessions,
            config->max_udp_sessions,
            config->max_udp_bindings);
        return 0;
    }
    errno = EMFILE;
    return -1;
}

static int start_with_config_unlocked(const char *path, const char *pid_path) {
    struct bpf2socks_runtime_config config;
    struct bpf2socks_policy_config policy;
    if (load_runtime_config(path, &config, &policy) < 0) return 2;
    if (bpf2socks_raise_memlock_limit() != 0) {
        fprintf(stderr, "failed to raise bpf2socks memlock limit: errno=%d\n", errno);
        return 1;
    }
    if (bpf2socks_raise_nofile_limit(BPF2SOCKS_DEFAULT_NOFILE_LIMIT) != 0) {
        fprintf(stderr, "failed to raise bpf2socks file descriptor limit: errno=%d\n", errno);
    }
    if (apply_nofile_session_capacity(&config) < 0) {
        fprintf(stderr, "insufficient file descriptor capacity for bpf2socks sessions: errno=%d\n", errno);
        return 1;
    }

    char message[256];
    if (bpf2socks_splice_probe(message, sizeof(message)) < 0) {
        fprintf(stderr, "bpf2socks splice relay is unavailable: %s\n", message);
        return 1;
    }
    if (bpf2socks_advanced_socket_probe(message, sizeof(message)) < 0) {
        fprintf(stderr, "bpf2socks advanced socket path is unavailable: %s\n", message);
        return 1;
    }

    struct bpf2socks_bpf_runtime runtime;
    if (bpf2socks_bpf_start(&config, &policy, &runtime) < 0) {
        int saved_errno = errno;
        cleanup_fixed_bpf_pins(&config);
        errno = saved_errno;
        fprintf(stderr, "failed to start bpf2socks BPF runtime: errno=%d\n", errno);
        return 1;
    }
    if (bpf2socks_stop_event_init() < 0) {
        int saved_errno = errno;
        bpf2socks_bpf_stop(&runtime);
        cleanup_fixed_bpf_pins(&config);
        errno = saved_errno;
        fprintf(stderr, "failed to create bpf2socks stop event: errno=%d\n", errno);
        return 1;
    }
    install_signal_handlers();
    config.token_map_fd = runtime.token_map_fd;
    config.reuseport_tcp4_map_fd = runtime.reuseport_tcp4_map_fd;
    config.reuseport_udp4_map_fd = runtime.reuseport_udp4_map_fd;
    config.reuseport_tcp6_map_fd = runtime.reuseport_tcp6_map_fd;
    config.reuseport_udp6_map_fd = runtime.reuseport_udp6_map_fd;
    config.reuseport_prog_fd = runtime.reuseport_prog_fd;
    int result = bpf2socks_bridge_run(&config, pid_path);
    uint32_t control_key = 0U;
    struct bpf2socks_tc_runtime_control control;
    if (runtime.tc_runtime_control_map_fd >= 0 &&
        bpf2socks_lookup_map(runtime.tc_runtime_control_map_fd, &control_key, &control) == 0) {
        control.enabled = 0U;
        (void)bpf2socks_update_map(runtime.tc_runtime_control_map_fd, &control_key, &control);
    }
    bpf2socks_bpf_stop(&runtime);
    bpf2socks_stop_event_close();
    cleanup_fixed_bpf_pins(&config);
    return result == 0 ? 0 : 1;
}

static int start_with_config(const char *path, const char *pid_path) {
    char lock_path[BPF2SOCKS_MAX_PATH_LEN];
    int written = snprintf(lock_path, sizeof(lock_path), "%s.lock", pid_path);
    if (written < 0 || (size_t)written >= sizeof(lock_path)) {
        errno = ENAMETOOLONG;
        fprintf(stderr, "bpf2socks instance lock path is too long\n");
        return 1;
    }
    int lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd < 0) {
        fprintf(stderr, "failed to open bpf2socks instance lock: errno=%d\n", errno);
        return 1;
    }
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        int saved_errno = errno;
        close(lock_fd);
        errno = saved_errno;
        fprintf(stderr, "bpf2socks is already running for this pid path: errno=%d\n", errno);
        return 1;
    }
    int result = start_with_config_unlocked(path, pid_path);
    int saved_errno = errno;
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    (void)unlink(lock_path);
    errno = saved_errno;
    return result;
}

static int stop_with_config(const char *path, const char *pid_path) {
    struct bpf2socks_runtime_config config;
    struct bpf2socks_policy_config policy;
    if (load_runtime_config(path, &config, &policy) < 0) return 0;
    FILE *file = fopen(pid_path, "r");
    if (file != NULL) {
        long pid = 0;
        if (fscanf(file, "%ld", &pid) == 1 && pid > 1L) {
            (void)kill((pid_t)pid, SIGTERM);
        }
        fclose(file);
    }
    (void)bpf2socks_detach_cgroup_path(config.cgroup_path);
    cleanup_fixed_bpf_pins(&config);
    return 0;
}

static void print_bridge_stats_json(const struct bpf2socks_bridge_stats *stats) {
    printf(
        "{"
        "\"tcpAccepts\":%" PRIu64 ","
        "\"tcpConnectFailures\":%" PRIu64 ","
        "\"tcpDropsCapacity\":%" PRIu64 ","
        "\"tcpConnectTimeouts\":%" PRIu64 ","
        "\"tcpIdleTimeouts\":%" PRIu64 ","
        "\"tcpFdExhaustions\":%" PRIu64 ","
        "\"tcpTokenDeleteFailures\":%" PRIu64 ","
        "\"tcpBytesClientToUpstream\":%" PRIu64 ","
        "\"tcpBytesUpstreamToClient\":%" PRIu64 ","
        "\"udpPacketsFromClient\":%" PRIu64 ","
        "\"udpPacketsToUpstream\":%" PRIu64 ","
        "\"udpPacketsFromUpstream\":%" PRIu64 ","
        "\"udpPacketsToClient\":%" PRIu64 ","
        "\"udpTokenMisses\":%" PRIu64 ","
        "\"udpSessionHits\":%" PRIu64 ","
        "\"udpSessionMisses\":%" PRIu64 ","
        "\"udpSessionEvictions\":%" PRIu64 ","
        "\"udpAssociateCreates\":%" PRIu64 ","
        "\"udpAssociateReuses\":%" PRIu64 ","
        "\"udpReplyBindingCreates\":%" PRIu64 ","
        "\"udpReplyBindingHits\":%" PRIu64 ","
        "\"udpFullconeBindingCreates\":%" PRIu64 ","
        "\"udpBindingEvictions\":%" PRIu64 ","
        "\"udpDropsMalformedSocks5\":%" PRIu64 ","
        "\"udpDropsOversized\":%" PRIu64 ","
        "\"udpDropsPendingBudget\":%" PRIu64 ","
        "\"udpPendingPeakBytes\":%" PRIu64 ","
        "\"udpSendErrors\":%" PRIu64 ","
        "\"dnsValidResponses\":%" PRIu64 ","
        "\"dnsTransactionTimeouts\":%" PRIu64 ","
        "\"dnsChannelTimeoutRebuilds\":%" PRIu64 ","
        "\"udpTokenLookupFullAttempts\":%" PRIu64 ","
        "\"udpTokenLookupFullHits\":%" PRIu64 ","
        "\"udpTokenLookupZeroAttempts\":%" PRIu64 ","
        "\"udpTokenLookupZeroHits\":%" PRIu64 ","
        "\"udpTokenLookupFallbacks\":%" PRIu64 ","
        "\"udpCopySends\":%" PRIu64 ","
        "\"udpBindingHashLookups\":%" PRIu64 ","
        "\"udpBindingHashCollisionSteps\":%" PRIu64 ","
        "\"dnsFreeStackAllocations\":%" PRIu64 ","
        "\"dnsFullTableEvictions\":%" PRIu64
        "}\n",
        stats->tcp_accepts,
        stats->tcp_connect_failures,
        stats->tcp_drops_capacity,
        stats->tcp_connect_timeouts,
        stats->tcp_idle_timeouts,
        stats->tcp_fd_exhaustions,
        stats->tcp_token_delete_failures,
        stats->tcp_bytes_client_to_upstream,
        stats->tcp_bytes_upstream_to_client,
        stats->udp_packets_from_client,
        stats->udp_packets_to_upstream,
        stats->udp_packets_from_upstream,
        stats->udp_packets_to_client,
        stats->udp_token_misses,
        stats->udp_session_hits,
        stats->udp_session_misses,
        stats->udp_session_evictions,
        stats->udp_associate_creates,
        stats->udp_associate_reuses,
        stats->udp_reply_binding_creates,
        stats->udp_reply_binding_hits,
        stats->udp_fullcone_binding_creates,
        stats->udp_binding_evictions,
        stats->udp_drops_malformed_socks5,
        stats->udp_drops_oversized,
        stats->udp_drops_pending_budget,
        stats->udp_pending_peak_bytes,
        stats->udp_send_errors,
        stats->dns_valid_responses,
        stats->dns_transaction_timeouts,
        stats->dns_channel_timeout_rebuilds,
        stats->udp_token_lookup_full_attempts,
        stats->udp_token_lookup_full_hits,
        stats->udp_token_lookup_zero_attempts,
        stats->udp_token_lookup_zero_hits,
        stats->udp_token_lookup_fallbacks,
        stats->udp_copy_sends,
        stats->udp_binding_hash_lookups,
        stats->udp_binding_hash_collision_steps,
        stats->dns_free_stack_allocations,
        stats->dns_full_table_evictions);
}

static int stats_with_pid(const char *pid_path) {
    struct bpf2socks_bridge_stats stats;
    if (bpf2socks_bridge_stats_dump(pid_path, &stats) < 0) {
        fprintf(stderr, "failed to read bpf2socks bridge stats: errno=%d\n", errno);
        return 1;
    }
    print_bridge_stats_json(&stats);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--probe") == 0) {
        return probe_with_config(config_path_arg(argc, argv));
    }
    if (argc >= 2 && strcmp(argv[1], "--start") == 0) {
        const char *path = config_path_arg(argc, argv);
        const char *pid_path = pid_path_arg(argc, argv);
        if (path == NULL || pid_path == NULL) {
            fprintf(stderr, "--start requires --config FILE --pid FILE\n");
            return 2;
        }
        return start_with_config(path, pid_path);
    }
    if (argc >= 2 && strcmp(argv[1], "--stop") == 0) {
        const char *path = config_path_arg(argc, argv);
        const char *pid_path = pid_path_arg(argc, argv);
        if (path == NULL || pid_path == NULL) {
            fprintf(stderr, "--stop requires --config FILE --pid FILE\n");
            return 2;
        }
        return stop_with_config(path, pid_path);
    }
    if (argc >= 2 && strcmp(argv[1], "--stats") == 0) {
        const char *pid_path = pid_path_arg(argc, argv);
        if (pid_path == NULL) {
            fprintf(stderr, "--stats requires --pid FILE\n");
            return 2;
        }
        return stats_with_pid(pid_path);
    }
    fprintf(stderr, "Usage: %s --probe [--config FILE] | --start --config FILE --pid FILE | --stop --config FILE --pid FILE | --stats --pid FILE\n", argv[0]);
    return 2;
}
