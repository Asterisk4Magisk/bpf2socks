// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf/runtime.h"
#include "bpf/cgroup_prog.h"
#include "bpf/policy.h"
#include "bpf/syscall.h"
#include "bpf2socks.h"
#include "core/log.h"
#include "core/util.h"
#include "kern/tc_token.h"
#include "shared/bpf_cgroup_owned.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* BPF runtime lifecycle: maps, policy loading, program attachment, probing and teardown. */

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif
/* BPF_MAP_TYPE_LRU_HASH. Android NDK headers expose it as an enum, not a preprocessor macro. */
#define BPF2SOCKS_TOKEN_MAP_TYPE 9U

static void init_runtime(struct bpf2socks_bpf_runtime *runtime) {
    memset(runtime, -1, sizeof(*runtime));
    runtime->interfaces = NULL;
    runtime->networks = NULL;
    runtime->udp6_recovery_attached = false;
    runtime->udp6_recovery_qdisc_created = false;
}

static uint32_t uid_map_max_entries(const struct bpf2socks_policy_config *policy) {
    size_t count = 0U;
    if (policy != NULL) {
        count = policy->uid_count + policy->bypass_uid_count;
    }
    if (count < 16U) return 16U;
    return count > UINT32_MAX ? UINT32_MAX : (uint32_t)count;
}

static bool uid_map_required(const struct bpf2socks_policy_config *policy) {
    if (policy == NULL) return false;
    if (policy->mode != BPF2SOCKS_MODE_GLOBAL) return true;
    return policy->bypass_uid_count > bpf2socks_cgroup_prog_inline_bypass_uid_count(policy);
}

static bool proxy_cidr4_map_required(const struct bpf2socks_policy_config *policy) {
    return policy != NULL && policy->proxy_private_cidr_v4_count > 0U;
}

static bool bypass_private_cidr4_map_required(const struct bpf2socks_policy_config *policy) {
    return policy != NULL &&
        policy->bypass_private_cidr_v4_count > 0U;
}

static bool direct_cidr4_map_required(const struct bpf2socks_policy_config *policy) {
    return policy != NULL && policy->bypass_direct_cidrs;
}

static bool proxy_cidr6_map_required(const struct bpf2socks_policy_config *policy) {
    return policy != NULL && policy->enable_ipv6 && policy->proxy_private_cidr_v6_count > 0U;
}

static bool bypass_private_cidr6_map_required(const struct bpf2socks_policy_config *policy) {
    return policy != NULL &&
        policy->enable_ipv6 &&
        policy->bypass_private_cidr_v6_count > 0U;
}

static bool direct_cidr6_map_required(const struct bpf2socks_policy_config *policy) {
    return policy != NULL &&
        policy->enable_ipv6 &&
        policy->bypass_direct_cidrs;
}

static int create_token_map(uint32_t max_entries) {
    return bpf2socks_bpf_map_create(
        (enum bpf_map_type)BPF2SOCKS_TOKEN_MAP_TYPE,
        sizeof(struct bpf2socks_token_key),
        sizeof(struct bpf2socks_original_dst),
        max_entries,
        0U);
}

static int create_udp_peer_map(uint32_t max_entries) {
    return bpf2socks_bpf_map_create(
        (enum bpf_map_type)BPF2SOCKS_TOKEN_MAP_TYPE,
        sizeof(struct bpf2socks_udp_peer_key),
        sizeof(struct bpf2socks_udp_peer_value),
        max_entries,
        0U);
}

/* netId -> present; BPF2SOCKS_DEFAULT_NETWORK_READY_KEY marks the set as known. */
static int create_default_network_map(void) {
    return bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_HASH,
        sizeof(uint32_t),
        sizeof(uint8_t),
        BPF2SOCKS_MAX_DEFAULT_NETWORK_MAP_ENTRIES,
        0U);
}

static int create_lpm4_map(uint32_t max_entries) {
    return bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct bpf2socks_lpm4_key),
        sizeof(uint8_t),
        max_entries,
        BPF_F_NO_PREALLOC);
}

static int create_lpm6_map(uint32_t max_entries) {
    return bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct bpf2socks_lpm6_key),
        sizeof(uint8_t),
        max_entries,
        BPF_F_NO_PREALLOC);
}

static int pin_local_address_map(
    const struct bpf2socks_runtime_config *config,
    int map_fd,
    const char *name) {
    char path[BPF2SOCKS_MAX_PATH_LEN];
    size_t directory_length = strlen(config->pinned_object_dir);
    const char *separator = directory_length > 0U && config->pinned_object_dir[directory_length - 1U] == '/' ? "" : "/";
    int written = snprintf(path, sizeof(path), "%s%s%s", config->pinned_object_dir, separator, name);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return bpf2socks_bpf_obj_pin(map_fd, path);
}

/* GETPEERNAME hooks arrived after UDP SENDMSG/RECVMSG. Keep older kernels
 * usable, but only treat an unsupported no-op hook as optional: a failure in
 * our real program on a supported hook must still fail startup/probing. */
static int attach_getpeername_prog(
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    int tcp_peer_map_fd,
    int cgroup_fd,
    bool ipv6,
    int *prog_fd,
    bool log_error) {
    enum bpf_attach_type type = ipv6 ? BPF_CGROUP_INET6_GETPEERNAME : BPF_CGROUP_INET4_GETPEERNAME;
    int capability_fd = bpf2socks_cgroup_prog_load_noop(type, ipv6 ? "b2s_ppeer6" : "b2s_ppeer4");
    if (log_error && capability_fd >= 0 && asterisk_cgroup_pin(capability_fd, config->pinned_object_dir) != 0) {
        bpf2socks_close_fd(&capability_fd); return -1;
    }
    int result = capability_fd < 0 ? -1 : bpf2socks_bpf_prog_attach(cgroup_fd, capability_fd, type);
    int saved_errno = errno;
    if (result == 0 && bpf2socks_bpf_prog_detach(cgroup_fd, capability_fd, type) != 0) {
        bpf2socks_close_fd(&capability_fd); return -1;
    }
    if (log_error && capability_fd >= 0) {
        char path[BPF2SOCKS_MAX_PATH_LEN];
        if (asterisk_cgroup_path(path, sizeof(path), config->pinned_object_dir,
                ipv6 ? "cgroup_peer_cap6" : "cgroup_peer_cap4") != 0 ||
            (unlink(path) != 0 && errno != ENOENT)) { bpf2socks_close_fd(&capability_fd); return -1; }
    }
    bpf2socks_close_fd(&capability_fd);
    if (result < 0) {
        errno = saved_errno;
        if (errno != EINVAL && errno != EOPNOTSUPP) return -1;
        if (log_error) bpf2socks_log("cgroup UDP%d getpeername is unavailable; peer address translation disabled: errno=%d", ipv6 ? 6 : 4, errno);
        return 0;
    }
    *prog_fd = ipv6
        ? bpf2socks_cgroup_prog_build_reverse6(config, token_map_fd, tcp_peer_map_fd, type, "b2s_upeer6", log_error)
        : bpf2socks_cgroup_prog_build_reverse4(config, token_map_fd, tcp_peer_map_fd, type, "b2s_upeer4", log_error);
    if (*prog_fd < 0) return -1;
    if (log_error && asterisk_cgroup_pin(*prog_fd, config->pinned_object_dir) != 0) return -1;
    return bpf2socks_bpf_prog_attach(cgroup_fd, *prog_fd, type);
}

static int open_cgroup_path(const char *path) {
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

// Cleanup is best-effort: it must not turn a successful capability probe
// into an unsupported result or replace the original startup failure.
static void cleanup_probe_attachment(int cgroup_fd, int prog_fd, enum bpf_attach_type type) {
    if (bpf2socks_bpf_prog_detach(cgroup_fd, prog_fd, type) < 0) {
        bpf2socks_log("BPF hook %u probe cleanup failed; continuing: errno=%d",
            (unsigned)type, errno);
    }
}

int bpf2socks_bpf_runtime_probe(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_policy_config *policy,
    char *message,
    size_t message_size) {
    bool need_uid_map = uid_map_required(policy);
    struct bpf2socks_bpf_runtime probe;
    init_runtime(&probe);
    /*
     * TC programs reference the complete policy ABI, so every CIDR map exists;
     * an empty map keeps the conditional policy behavior.
     */
    probe.uid_map_fd = need_uid_map
        ? bpf2socks_bpf_map_create(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), 16U, 0U)
        : -1;
    probe.proxy_cidr4_map_fd = create_lpm4_map(16U);
    probe.bypass_private_cidr4_map_fd = create_lpm4_map(16U);
    probe.local_interface_cidr4_map_fd = create_lpm4_map(16U);
    probe.direct_cidr4_map_fd = create_lpm4_map(16U);
    probe.token_map_fd = create_token_map(16U);
    probe.udp_peer_map_fd = create_udp_peer_map(16U);
    probe.tcp_peer_map_fd = create_udp_peer_map(16U);
    probe.default_network_map_fd = create_default_network_map();
    probe.proxy_cidr6_map_fd = create_lpm6_map(16U);
    probe.bypass_private_cidr6_map_fd = create_lpm6_map(16U);
    probe.local_interface_cidr6_map_fd = create_lpm6_map(16U);
    probe.direct_cidr6_map_fd = create_lpm6_map(16U);
    bool interface_policy_enabled = policy->ignored_interface_count > 0U;
    probe.ignored_ifindex_map_fd = interface_policy_enabled
        ? bpf2socks_bpf_map_create(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint8_t), 16U, 0U)
        : -1;
    probe.ignored_route_cidr4_map_fd = interface_policy_enabled
        ? create_lpm4_map(16U)
        : -1;
    probe.ignored_route_cidr6_map_fd = interface_policy_enabled && policy->enable_ipv6
        ? create_lpm6_map(16U)
        : -1;
    int cgroup_fd = -1;
    int connect4_fd = -1;
    int connect6_fd = -1;
    int connect6_v4mapped_fd = -1;
    int udp4_fd = -1;
    int udp6_fd = -1;
    int udp4_peer_fd = -1;
    int udp6_peer_fd = -1;
    int udp4_recv_fd = -1;
    int udp6_recv_fd = -1;
    int noop_connect4_fd = -1;
    int noop_connect6_fd = -1;
    int noop_udp4_fd = -1;
    int noop_udp6_fd = -1;
    int tc_probe_fd = -1;
    int reuseport_probe_fd = -1;
    int result = -1;

    if ((need_uid_map && probe.uid_map_fd < 0) ||
        probe.proxy_cidr4_map_fd < 0 ||
        probe.bypass_private_cidr4_map_fd < 0 ||
        probe.local_interface_cidr4_map_fd < 0 ||
        probe.direct_cidr4_map_fd < 0 ||
        probe.token_map_fd < 0 ||
        probe.udp_peer_map_fd < 0 ||
        probe.tcp_peer_map_fd < 0 ||
        probe.default_network_map_fd < 0 ||
        probe.proxy_cidr6_map_fd < 0 ||
        probe.bypass_private_cidr6_map_fd < 0 ||
        probe.local_interface_cidr6_map_fd < 0 ||
        probe.direct_cidr6_map_fd < 0 ||
        (interface_policy_enabled && (probe.ignored_ifindex_map_fd < 0 || probe.ignored_route_cidr4_map_fd < 0 ||
            (policy->enable_ipv6 && probe.ignored_route_cidr6_map_fd < 0)))) {
        snprintf(message, message_size, "required bpf maps are unavailable: errno=%d", errno);
        goto done;
    }

    uint16_t bridge_port = config->listen_port;
    connect4_fd = bpf2socks_cgroup_prog_build4(
        policy,
        config,
        &probe,
        BPF2SOCKS_PROTO_TCP,
        true,
        bridge_port,
        BPF_CGROUP_INET4_CONNECT,
        "b2s_conn4",
        false);
    if (connect4_fd < 0) {
        snprintf(message, message_size, "cgroup connect4 program cannot be loaded: errno=%d", errno);
        goto done;
    }
    udp4_fd = bpf2socks_cgroup_prog_build4(
        policy,
        config,
        &probe,
        BPF2SOCKS_PROTO_UDP,
        false,
        bridge_port,
        BPF_CGROUP_UDP4_SENDMSG,
        "b2s_udp4",
        false);
    if (udp4_fd < 0) {
        snprintf(message, message_size, "cgroup udp4 sendmsg program cannot be loaded: errno=%d", errno);
        goto done;
    }
    udp4_recv_fd = bpf2socks_cgroup_prog_build_reverse4(config, probe.token_map_fd, -1, BPF_CGROUP_UDP4_RECVMSG, "b2s_urcv4", false);
    if (udp4_recv_fd < 0) {
        snprintf(message, message_size, "cgroup udp4 recvmsg program cannot be loaded: errno=%d", errno);
        goto done;
    }
    if (policy->enable_ipv6 || policy->enable_dns_hijack) {
        connect6_fd = bpf2socks_cgroup_prog_build6(
            policy,
            config,
            &probe,
            BPF2SOCKS_PROTO_TCP,
            true,
            bridge_port,
            BPF_CGROUP_INET6_CONNECT,
            "b2s_conn6",
            false);
        udp6_fd = bpf2socks_cgroup_prog_build6(
            policy,
            config,
            &probe,
            BPF2SOCKS_PROTO_UDP,
            false,
            bridge_port,
            BPF_CGROUP_UDP6_SENDMSG,
            "b2s_udp6",
            false);
        udp6_recv_fd = bpf2socks_cgroup_prog_build_reverse6(config, probe.token_map_fd, -1, BPF_CGROUP_UDP6_RECVMSG, "b2s_urcv6", false);
        if (connect6_fd < 0 || udp6_fd < 0 || udp6_recv_fd < 0) {
            snprintf(message, message_size, "cgroup IPv6 programs cannot be loaded: errno=%d", errno);
            goto done;
        }
    } else {
        connect6_v4mapped_fd = bpf2socks_cgroup_prog_build_mapped6(
            policy,
            config,
            &probe,
            BPF2SOCKS_PROTO_TCP,
            true,
            bridge_port,
            BPF_CGROUP_INET6_CONNECT,
            "b2s_c6v4m",
            false);
        if (connect6_v4mapped_fd < 0) {
            snprintf(message, message_size, "cgroup IPv4-mapped connect6 program cannot be loaded: errno=%d", errno);
            goto done;
        }
        udp6_fd = bpf2socks_cgroup_prog_build_mapped6(
            policy,
            config,
            &probe,
            BPF2SOCKS_PROTO_UDP,
            false,
            bridge_port,
            BPF_CGROUP_UDP6_SENDMSG,
            "b2s_u6v4m",
            false);
        udp6_recv_fd = bpf2socks_cgroup_prog_build_reverse6(config, probe.token_map_fd, -1, BPF_CGROUP_UDP6_RECVMSG, "b2s_ur6v4m", false);
        if (udp6_fd < 0 || udp6_recv_fd < 0) {
            snprintf(message, message_size, "cgroup IPv4-mapped udp6 programs cannot be loaded: errno=%d", errno);
            goto done;
        }
    }

    cgroup_fd = open_cgroup_path(config->cgroup_path);
    if (cgroup_fd < 0) {
        snprintf(message, message_size, "cgroup path cannot be opened: errno=%d", errno);
        goto done;
    }

    noop_connect4_fd = bpf2socks_cgroup_prog_load_noop(BPF_CGROUP_INET4_CONNECT, "b2s_pconn4");
    noop_udp4_fd = bpf2socks_cgroup_prog_load_noop(BPF_CGROUP_UDP4_SENDMSG, "b2s_pudp4");
    bool need_connect6_attach = connect6_fd >= 0 || connect6_v4mapped_fd >= 0;
    bool need_udp6_attach = policy->enable_ipv6 || udp6_fd >= 0 || udp6_recv_fd >= 0;
    if (need_connect6_attach) {
        noop_connect6_fd = bpf2socks_cgroup_prog_load_noop(BPF_CGROUP_INET6_CONNECT, "b2s_pconn6");
    }
    if (need_udp6_attach) {
        noop_udp6_fd = bpf2socks_cgroup_prog_load_noop(BPF_CGROUP_UDP6_SENDMSG, "b2s_pudp6");
    }
    if (noop_connect4_fd < 0 || noop_udp4_fd < 0 ||
        (need_connect6_attach && noop_connect6_fd < 0) ||
        (need_udp6_attach && noop_udp6_fd < 0)) {
        snprintf(message, message_size, "cgroup probe program cannot be loaded: errno=%d", errno);
        goto done;
    }
    if (bpf2socks_bpf_prog_attach(cgroup_fd, noop_connect4_fd, BPF_CGROUP_INET4_CONNECT) < 0) {
        snprintf(message, message_size, "cgroup connect4 attach is unavailable: errno=%d", errno);
        goto done;
    }
    cleanup_probe_attachment(cgroup_fd, noop_connect4_fd, BPF_CGROUP_INET4_CONNECT);
    if (bpf2socks_bpf_prog_attach(cgroup_fd, noop_udp4_fd, BPF_CGROUP_UDP4_SENDMSG) < 0) {
        snprintf(message, message_size, "cgroup udp4 sendmsg attach is unavailable: errno=%d", errno);
        goto done;
    }
    cleanup_probe_attachment(cgroup_fd, noop_udp4_fd, BPF_CGROUP_UDP4_SENDMSG);
    if (bpf2socks_bpf_prog_attach(cgroup_fd, udp4_recv_fd, BPF_CGROUP_UDP4_RECVMSG) < 0) {
        snprintf(message, message_size, "cgroup udp4 recvmsg attach is unavailable: errno=%d", errno);
        goto done;
    }
    cleanup_probe_attachment(cgroup_fd, udp4_recv_fd, BPF_CGROUP_UDP4_RECVMSG);
    if (need_connect6_attach) {
        if (bpf2socks_bpf_prog_attach(cgroup_fd, noop_connect6_fd, BPF_CGROUP_INET6_CONNECT) < 0) {
            snprintf(message, message_size, "cgroup connect6 attach is unavailable: errno=%d", errno);
            goto done;
        }
        cleanup_probe_attachment(cgroup_fd, noop_connect6_fd, BPF_CGROUP_INET6_CONNECT);
    }
    if (need_udp6_attach) {
        if (bpf2socks_bpf_prog_attach(cgroup_fd, noop_udp6_fd, BPF_CGROUP_UDP6_SENDMSG) < 0) {
            snprintf(message, message_size, "cgroup udp6 sendmsg attach is unavailable: errno=%d", errno);
            goto done;
        }
        cleanup_probe_attachment(cgroup_fd, noop_udp6_fd, BPF_CGROUP_UDP6_SENDMSG);
        if (bpf2socks_bpf_prog_attach(cgroup_fd, udp6_recv_fd, BPF_CGROUP_UDP6_RECVMSG) < 0) {
            snprintf(message, message_size, "cgroup udp6 recvmsg attach is unavailable: errno=%d", errno);
            goto done;
        }
        cleanup_probe_attachment(cgroup_fd, udp6_recv_fd, BPF_CGROUP_UDP6_RECVMSG);
    }
    if (attach_getpeername_prog(config, probe.token_map_fd, probe.tcp_peer_map_fd, cgroup_fd, false, &udp4_peer_fd, false) < 0 ||
        (need_udp6_attach &&
            attach_getpeername_prog(config, probe.token_map_fd, probe.tcp_peer_map_fd, cgroup_fd, true, &udp6_peer_fd, false) < 0)) {
        snprintf(message, message_size, "cgroup udp getpeername program unavailable: errno=%d", errno);
        goto done;
    }
    if (policy->hotspot_interface_prefix_count > 0U) {
        tc_probe_fd = bpf2socks_cgroup_prog_load_constant(
            BPF_PROG_TYPE_SCHED_CLS,
            (enum bpf_attach_type)0,
            3,
            "b2s_ptc");
        reuseport_probe_fd = bpf2socks_cgroup_prog_load_constant(
            BPF_PROG_TYPE_SK_REUSEPORT,
            BPF_SK_REUSEPORT_SELECT,
            1,
            "b2s_preuse");
        if (tc_probe_fd < 0 || reuseport_probe_fd < 0) {
            snprintf(message, message_size, "TC/reuseport programs cannot be loaded: errno=%d", errno);
            goto done;
        }
    }

    snprintf(message, message_size, "ok");
    result = 0;

done:
    (void)bpf2socks_bpf_cgroup_restore(cgroup_fd);
    if (udp4_peer_fd >= 0) (void)bpf2socks_bpf_prog_detach(cgroup_fd, udp4_peer_fd, BPF_CGROUP_INET4_GETPEERNAME);
    if (udp6_peer_fd >= 0) (void)bpf2socks_bpf_prog_detach(cgroup_fd, udp6_peer_fd, BPF_CGROUP_INET6_GETPEERNAME);
    bpf2socks_close_fd(&udp4_peer_fd);
    bpf2socks_close_fd(&udp6_peer_fd);
    bpf2socks_close_fd(&reuseport_probe_fd);
    bpf2socks_close_fd(&tc_probe_fd);
    bpf2socks_close_fd(&noop_udp6_fd);
    bpf2socks_close_fd(&noop_connect6_fd);
    bpf2socks_close_fd(&noop_udp4_fd);
    bpf2socks_close_fd(&noop_connect4_fd);
    bpf2socks_close_fd(&udp6_recv_fd);
    bpf2socks_close_fd(&udp4_recv_fd);
    bpf2socks_close_fd(&udp6_fd);
    bpf2socks_close_fd(&udp4_fd);
    bpf2socks_close_fd(&connect6_v4mapped_fd);
    bpf2socks_close_fd(&connect6_fd);
    bpf2socks_close_fd(&connect4_fd);
    bpf2socks_close_fd(&cgroup_fd);
    bpf2socks_close_fd(&probe.ignored_route_cidr6_map_fd);
    bpf2socks_close_fd(&probe.ignored_route_cidr4_map_fd);
    bpf2socks_close_fd(&probe.ignored_ifindex_map_fd);
    bpf2socks_close_fd(&probe.direct_cidr6_map_fd);
    bpf2socks_close_fd(&probe.local_interface_cidr6_map_fd);
    bpf2socks_close_fd(&probe.bypass_private_cidr6_map_fd);
    bpf2socks_close_fd(&probe.proxy_cidr6_map_fd);
    bpf2socks_close_fd(&probe.udp_peer_map_fd);
    bpf2socks_close_fd(&probe.tcp_peer_map_fd);
    bpf2socks_close_fd(&probe.default_network_map_fd);
    bpf2socks_close_fd(&probe.token_map_fd);
    bpf2socks_close_fd(&probe.direct_cidr4_map_fd);
    bpf2socks_close_fd(&probe.local_interface_cidr4_map_fd);
    bpf2socks_close_fd(&probe.bypass_private_cidr4_map_fd);
    bpf2socks_close_fd(&probe.proxy_cidr4_map_fd);
    bpf2socks_close_fd(&probe.uid_map_fd);
    return result;
}

int bpf2socks_bpf_runtime_start(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_policy_config *policy,
    struct bpf2socks_bpf_runtime *runtime) {
    if (runtime == NULL || config == NULL || policy == NULL) {
        errno = EINVAL;
        return -1;
    }
    init_runtime(runtime);
    char stage_detail[96];
    const char *stage = "init";
    bool interface_policy_enabled = policy->ignored_interface_count > 0U;
    bool need_uid_map = uid_map_required(policy);
    /*
     * TC programs reference the complete policy ABI, so every CIDR map exists;
     * an empty map keeps the conditional policy behavior.
     */

    if (need_uid_map) {
        uint32_t uid_entries = uid_map_max_entries(policy);
        snprintf(stage_detail, sizeof(stage_detail), "create uid map (%u entries)", uid_entries);
        stage = stage_detail;
        runtime->uid_map_fd = bpf2socks_bpf_map_create(
            BPF_MAP_TYPE_HASH,
            sizeof(uint32_t),
            sizeof(uint32_t),
            uid_entries,
            0U);
        if (runtime->uid_map_fd < 0) goto fail;
    }
    stage = "create proxy cidr4 map";
    runtime->proxy_cidr4_map_fd = create_lpm4_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
    if (runtime->proxy_cidr4_map_fd < 0) goto fail;
    stage = "create bypass private cidr4 map";
    runtime->bypass_private_cidr4_map_fd = create_lpm4_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
    if (runtime->bypass_private_cidr4_map_fd < 0) goto fail;
    stage = "create local interface cidr4 map";
    runtime->local_interface_cidr4_map_fd = create_lpm4_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
    if (runtime->local_interface_cidr4_map_fd < 0) goto fail;
    stage = "pin local address v4 map";
    if (pin_local_address_map(config, runtime->local_interface_cidr4_map_fd, "local_addr_v4") < 0) goto fail;
    stage = "create direct cidr4 map";
    runtime->direct_cidr4_map_fd = create_lpm4_map(BPF2SOCKS_MAX_DIRECT_CIDR_MAP_ENTRIES);
    if (runtime->direct_cidr4_map_fd < 0) goto fail;
    stage = "create token map";
    runtime->token_map_fd = create_token_map(BPF2SOCKS_MAX_TOKEN_MAP_ENTRIES);
    if (runtime->token_map_fd < 0) goto fail;
    stage = "create udp peer map";
    runtime->udp_peer_map_fd = create_udp_peer_map(BPF2SOCKS_MAX_UDP_PEER_MAP_ENTRIES);
    if (runtime->udp_peer_map_fd < 0) goto fail;
    stage = "create tcp peer map";
    runtime->tcp_peer_map_fd = create_udp_peer_map(BPF2SOCKS_MAX_TCP_PEER_MAP_ENTRIES);
    if (runtime->tcp_peer_map_fd < 0) goto fail;
    stage = "create default network map";
    runtime->default_network_map_fd = create_default_network_map();
    if (runtime->default_network_map_fd < 0) goto fail;
    stage = "create TC runtime control map";
    runtime->tc_runtime_control_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t),
        sizeof(struct bpf2socks_tc_runtime_control),
        1U,
        0U);
    if (runtime->tc_runtime_control_map_fd < 0) goto fail;
    stage = "create TC original token map";
    runtime->tc_original_to_token_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct bpf2socks_tc_original_key),
        sizeof(struct bpf2socks_tc_token_value),
        BPF2SOCKS_MAX_TOKEN_MAP_ENTRIES,
        0U);
    if (runtime->tc_original_to_token_map_fd < 0) goto fail;
    stage = "create TC reverse token map";
    runtime->tc_token_to_original_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct bpf2socks_tc_reverse_key),
        sizeof(struct bpf2socks_tc_original_value),
        BPF2SOCKS_MAX_TOKEN_MAP_ENTRIES,
        0U);
    if (runtime->tc_token_to_original_map_fd < 0) goto fail;
    stage = "create TC scratch map";
    runtime->tc_scratch_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_PERCPU_ARRAY,
        sizeof(uint32_t),
        BPF2SOCKS_TC_SCRATCH_ABI_SIZE,
        1U,
        0U);
    if (runtime->tc_scratch_map_fd < 0) goto fail;
    stage = "create TC fragment map";
    runtime->tc_fragment_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct bpf2socks_tc_fragment_key),
        sizeof(struct bpf2socks_tc_fragment_value),
        BPF2SOCKS_TC_FRAGMENT_MAP_ENTRIES,
        0U);
    if (runtime->tc_fragment_map_fd < 0) goto fail;
    stage = "create reuseport maps";
    runtime->reuseport_tcp4_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
        sizeof(uint32_t),
        sizeof(uint32_t),
        BPF2SOCKS_MAX_WORKER_COUNT,
        0U);
    runtime->reuseport_udp4_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
        sizeof(uint32_t),
        sizeof(uint32_t),
        BPF2SOCKS_MAX_WORKER_COUNT,
        0U);
    runtime->reuseport_tcp6_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
        sizeof(uint32_t),
        sizeof(uint32_t),
        BPF2SOCKS_MAX_WORKER_COUNT,
        0U);
    runtime->reuseport_udp6_map_fd = bpf2socks_bpf_map_create(
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
        sizeof(uint32_t),
        sizeof(uint32_t),
        BPF2SOCKS_MAX_WORKER_COUNT,
        0U);
    if (runtime->reuseport_tcp4_map_fd < 0 ||
        runtime->reuseport_udp4_map_fd < 0 ||
        runtime->reuseport_tcp6_map_fd < 0 ||
        runtime->reuseport_udp6_map_fd < 0) {
        goto fail;
    }
    stage = "create proxy cidr6 map";
    runtime->proxy_cidr6_map_fd = create_lpm6_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
    if (runtime->proxy_cidr6_map_fd < 0) goto fail;
    stage = "create bypass private cidr6 map";
    runtime->bypass_private_cidr6_map_fd = create_lpm6_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
    if (runtime->bypass_private_cidr6_map_fd < 0) goto fail;
    stage = "create local interface cidr6 map";
    runtime->local_interface_cidr6_map_fd = create_lpm6_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
    if (runtime->local_interface_cidr6_map_fd < 0) goto fail;
    stage = "pin local address v6 map";
    if (pin_local_address_map(config, runtime->local_interface_cidr6_map_fd, "local_addr_v6") < 0) goto fail;
    stage = "create direct cidr6 map";
    runtime->direct_cidr6_map_fd = create_lpm6_map(BPF2SOCKS_MAX_DIRECT_CIDR_MAP_ENTRIES);
    if (runtime->direct_cidr6_map_fd < 0) goto fail;
    if (interface_policy_enabled) {
        stage = "create ignored ifindex map";
        runtime->ignored_ifindex_map_fd = bpf2socks_bpf_map_create(
            BPF_MAP_TYPE_HASH,
            sizeof(uint32_t),
            sizeof(uint8_t),
            BPF2SOCKS_MAX_INTERFACES,
            0U);
        if (runtime->ignored_ifindex_map_fd < 0) goto fail;
        stage = "create ignored route cidr4 map";
        runtime->ignored_route_cidr4_map_fd = create_lpm4_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
        if (runtime->ignored_route_cidr4_map_fd < 0) goto fail;
        if (policy->enable_ipv6) {
            stage = "create ignored route cidr6 map";
            runtime->ignored_route_cidr6_map_fd = create_lpm6_map(BPF2SOCKS_MAX_CIDR_MAP_ENTRIES);
            if (runtime->ignored_route_cidr6_map_fd < 0) goto fail;
        }
    }
    if (need_uid_map && bpf2socks_policy_load_uids(runtime->uid_map_fd, policy) < 0) {
        stage = "load uid map";
        goto fail;
    }
    if (proxy_cidr4_map_required(policy) &&
        bpf2socks_policy_load_cidr_list(
            runtime->proxy_cidr4_map_fd,
            policy->proxy_private_cidrs_v4,
            policy->proxy_private_cidr_v4_count,
            AF_INET) < 0) {
        stage = "load proxy cidr4 map";
        goto fail;
    }
    if (bypass_private_cidr4_map_required(policy) &&
        bpf2socks_policy_load_cidr_list(runtime->bypass_private_cidr4_map_fd, policy->bypass_private_cidrs_v4, policy->bypass_private_cidr_v4_count, AF_INET) < 0) {
        stage = "load bypass private cidr4 map";
        goto fail;
    }
    if (direct_cidr4_map_required(policy) &&
        bpf2socks_policy_load_cidr_file(runtime->direct_cidr4_map_fd, policy->direct_cidr_path_v4, AF_INET) < 0) {
        stage = "load direct cidr4 map";
        goto fail;
    }
    if (proxy_cidr6_map_required(policy) &&
        bpf2socks_policy_load_cidr_list(runtime->proxy_cidr6_map_fd, policy->proxy_private_cidrs_v6, policy->proxy_private_cidr_v6_count, AF_INET6) < 0) {
        stage = "load proxy cidr6 map";
        goto fail;
    }
    if (bypass_private_cidr6_map_required(policy) &&
        bpf2socks_policy_load_cidr_list(runtime->bypass_private_cidr6_map_fd, policy->bypass_private_cidrs_v6, policy->bypass_private_cidr_v6_count, AF_INET6) < 0) {
        stage = "load bypass private cidr6 map";
        goto fail;
    }
    if (direct_cidr6_map_required(policy) &&
        bpf2socks_policy_load_cidr_file(runtime->direct_cidr6_map_fd, policy->direct_cidr_path_v6, AF_INET6) < 0) {
        stage = "load direct cidr6 map";
        goto fail;
    }

    uint32_t control_key = 0U;
    struct bpf2socks_tc_runtime_control control;
    memset(&control, 0, sizeof(control));
    control.enabled = BPF2SOCKS_TC_RUNTIME_ENABLED;
    control.generation = 1U;
    control.bridge_port = config->listen_port;
    if (policy->enable_ipv6) control.flags |= BPF2SOCKS_TC_RUNTIME_IPV6;
    if (policy->enable_dns_hijack) control.flags |= BPF2SOCKS_TC_RUNTIME_DNS_HIJACK;
    if (policy->bypass_direct_cidrs) control.flags |= BPF2SOCKS_TC_RUNTIME_BYPASS_DIRECT;
    memcpy(control.token_ipv4_prefix, config->token_ipv4_prefix, sizeof(control.token_ipv4_prefix));
    memcpy(control.token_ipv6_prefix, config->token_ipv6_prefix, sizeof(control.token_ipv6_prefix));
    control.worker_count = config->worker_count;
    stage = "initialize TC runtime control";
    if (bpf2socks_bpf_map_update(runtime->tc_runtime_control_map_fd, &control_key, &control) < 0) {
        goto fail;
    }
    stage = "load embedded TC programs";
    if (bpf2socks_bpf_object_load_tc_programs(config, policy, runtime, true) < 0) {
        goto fail;
    }

    runtime->cgroup_fd = open_cgroup_path(config->cgroup_path);
    if (runtime->cgroup_fd < 0) {
        stage = "open cgroup";
        goto fail;
    }
    if (asterisk_cgroup_reconcile(config->cgroup_path, config->pinned_object_dir) < 0) {
        stage = "detach previous cgroup programs";
        goto fail;
    }
    runtime->connect4_prog_fd = bpf2socks_cgroup_prog_build4(
        policy,
        config,
        runtime,
        BPF2SOCKS_PROTO_TCP,
        true,
        config->listen_port,
        BPF_CGROUP_INET4_CONNECT,
        "b2s_conn4",
        true);
    runtime->udp4_sendmsg_prog_fd = bpf2socks_cgroup_prog_build4(
        policy,
        config,
        runtime,
        BPF2SOCKS_PROTO_UDP,
        false,
        config->listen_port,
        BPF_CGROUP_UDP4_SENDMSG,
        "b2s_udp4",
        true);
    runtime->udp4_recvmsg_prog_fd = bpf2socks_cgroup_prog_build_reverse4(
        config,
        runtime->token_map_fd,
        -1,
        BPF_CGROUP_UDP4_RECVMSG,
        "b2s_urcv4",
        true);
    if (runtime->connect4_prog_fd < 0 || runtime->udp4_sendmsg_prog_fd < 0 || runtime->udp4_recvmsg_prog_fd < 0) {
        stage = "load cgroup programs";
        goto fail;
    }
    if (policy->enable_ipv6 || policy->enable_dns_hijack) {
        runtime->connect6_prog_fd = bpf2socks_cgroup_prog_build6(
            policy,
            config,
            runtime,
            BPF2SOCKS_PROTO_TCP,
            true,
            config->listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "b2s_conn6",
            true);
        runtime->udp6_sendmsg_prog_fd = bpf2socks_cgroup_prog_build6(
            policy,
            config,
            runtime,
            BPF2SOCKS_PROTO_UDP,
            false,
            config->listen_port,
            BPF_CGROUP_UDP6_SENDMSG,
            "b2s_udp6",
            true);
        runtime->udp6_recvmsg_prog_fd = bpf2socks_cgroup_prog_build_reverse6(
            config,
            runtime->token_map_fd,
            -1,
            BPF_CGROUP_UDP6_RECVMSG,
            "b2s_urcv6",
            true);
        if (runtime->connect6_prog_fd < 0 ||
            runtime->udp6_sendmsg_prog_fd < 0 ||
            runtime->udp6_recvmsg_prog_fd < 0) {
            stage = "load cgroup IPv6 programs";
            goto fail;
        }
    } else {
        runtime->connect6_v4mapped_prog_fd = bpf2socks_cgroup_prog_build_mapped6(
            policy,
            config,
            runtime,
            BPF2SOCKS_PROTO_TCP,
            true,
            config->listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "b2s_c6v4m",
            true);
        if (runtime->connect6_v4mapped_prog_fd < 0) {
            stage = "load cgroup IPv4-mapped connect6 program";
            goto fail;
        }
        runtime->udp6_v4mapped_sendmsg_prog_fd = bpf2socks_cgroup_prog_build_mapped6(
            policy,
            config,
            runtime,
            BPF2SOCKS_PROTO_UDP,
            false,
            config->listen_port,
            BPF_CGROUP_UDP6_SENDMSG,
            "b2s_u6v4m",
            true);
        runtime->udp6_v4mapped_recvmsg_prog_fd = bpf2socks_cgroup_prog_build_reverse6(
            config,
            runtime->token_map_fd,
            -1,
            BPF_CGROUP_UDP6_RECVMSG,
            "b2s_ur6v4m",
            true);
        if (runtime->udp6_v4mapped_sendmsg_prog_fd < 0 ||
            runtime->udp6_v4mapped_recvmsg_prog_fd < 0) {
            stage = "load cgroup IPv4-mapped udp6 programs";
            goto fail;
        }
    }
    if (bpf2socks_udp6_recovery_start(runtime) < 0) {
        stage = "attach UDP6 recovery";
        goto fail;
    }
    if (bpf2socks_interface_policy_start(policy, runtime) < 0) {
        stage = "start interface policy";
        goto fail;
    }
    /* Without the watcher the default network set stays unknown and nothing extra is bypassed. */
    if (bpf2socks_network_selection_start(runtime) < 0) {
        bpf2socks_log("default network watcher is unavailable; explicitly bound sockets stay proxied: errno=%d", errno);
    }
    stage = "pin cgroup program identity";
    if (runtime->connect4_prog_fd >= 0 && asterisk_cgroup_pin(runtime->connect4_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->connect6_prog_fd >= 0 && asterisk_cgroup_pin(runtime->connect6_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->connect6_v4mapped_prog_fd >= 0 && asterisk_cgroup_pin(runtime->connect6_v4mapped_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->udp4_sendmsg_prog_fd >= 0 && asterisk_cgroup_pin(runtime->udp4_sendmsg_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->udp6_sendmsg_prog_fd >= 0 && asterisk_cgroup_pin(runtime->udp6_sendmsg_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->udp6_v4mapped_sendmsg_prog_fd >= 0 && asterisk_cgroup_pin(runtime->udp6_v4mapped_sendmsg_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->udp4_recvmsg_prog_fd >= 0 && asterisk_cgroup_pin(runtime->udp4_recvmsg_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->udp6_recvmsg_prog_fd >= 0 && asterisk_cgroup_pin(runtime->udp6_recvmsg_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (runtime->udp6_v4mapped_recvmsg_prog_fd >= 0 && asterisk_cgroup_pin(runtime->udp6_v4mapped_recvmsg_prog_fd, config->pinned_object_dir) != 0) goto fail;
    if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->connect4_prog_fd, BPF_CGROUP_INET4_CONNECT) < 0) {
        stage = "attach connect4";
        goto fail;
    }
    if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->udp4_sendmsg_prog_fd, BPF_CGROUP_UDP4_SENDMSG) < 0) {
        (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect4_prog_fd, BPF_CGROUP_INET4_CONNECT);
        stage = "attach udp4 sendmsg";
        goto fail;
    }
    if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->udp4_recvmsg_prog_fd, BPF_CGROUP_UDP4_RECVMSG) < 0) {
        (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp4_sendmsg_prog_fd, BPF_CGROUP_UDP4_SENDMSG);
        (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect4_prog_fd, BPF_CGROUP_INET4_CONNECT);
        stage = "attach udp4 recvmsg";
        goto fail;
    }
    if (policy->enable_ipv6 || policy->enable_dns_hijack) {
        if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->connect6_prog_fd, BPF_CGROUP_INET6_CONNECT) < 0) {
            stage = "attach connect6";
            goto fail;
        }
        if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->udp6_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG) < 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect6_prog_fd, BPF_CGROUP_INET6_CONNECT);
            stage = "attach udp6 sendmsg";
            goto fail;
        }
        if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->udp6_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG) < 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp6_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG);
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect6_prog_fd, BPF_CGROUP_INET6_CONNECT);
            stage = "attach udp6 recvmsg";
            goto fail;
        }
    } else {
        if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->connect6_v4mapped_prog_fd, BPF_CGROUP_INET6_CONNECT) < 0) {
            stage = "attach connect6 v4mapped";
            goto fail;
        }
        if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->udp6_v4mapped_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG) < 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect6_v4mapped_prog_fd, BPF_CGROUP_INET6_CONNECT);
            stage = "attach udp6 sendmsg v4mapped";
            goto fail;
        }
        if (bpf2socks_bpf_prog_attach(runtime->cgroup_fd, runtime->udp6_v4mapped_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG) < 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp6_v4mapped_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG);
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect6_v4mapped_prog_fd, BPF_CGROUP_INET6_CONNECT);
            stage = "attach udp6 recvmsg v4mapped";
            goto fail;
        }
    }
    stage = "attach udp getpeername";
    if (attach_getpeername_prog(config, runtime->token_map_fd, runtime->tcp_peer_map_fd,
            runtime->cgroup_fd, false, &runtime->udp4_getpeername_prog_fd, true) < 0 ||
        attach_getpeername_prog(config, runtime->token_map_fd, runtime->tcp_peer_map_fd,
            runtime->cgroup_fd, true, &runtime->udp6_getpeername_prog_fd, true) < 0) goto fail;
    return 0;

fail:
    bpf2socks_log("failed to start BPF runtime at stage '%s': errno=%d", stage, errno);
    bpf2socks_bpf_runtime_stop(runtime);
    return -1;
}

void bpf2socks_bpf_runtime_stop(struct bpf2socks_bpf_runtime *runtime) {
    if (runtime == NULL) return;
    bpf2socks_interface_policy_stop(runtime);
    bpf2socks_network_selection_stop(runtime);
    bpf2socks_udp6_recovery_stop(runtime);
    bpf2socks_close_fd(&runtime->udp6_record_prog_fd);
    bpf2socks_close_fd(&runtime->udp6_recover_prog_fd);
    bpf2socks_close_fd(&runtime->udp6_recovery_map_fd);
    if (runtime->cgroup_fd >= 0) {
        if (runtime->udp4_getpeername_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp4_getpeername_prog_fd, BPF_CGROUP_INET4_GETPEERNAME);
        }
        if (runtime->udp6_getpeername_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp6_getpeername_prog_fd, BPF_CGROUP_INET6_GETPEERNAME);
        }
        if (runtime->udp6_recvmsg_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp6_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG);
        }
        if (runtime->udp6_sendmsg_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp6_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG);
        }
        if (runtime->udp6_v4mapped_recvmsg_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp6_v4mapped_recvmsg_prog_fd, BPF_CGROUP_UDP6_RECVMSG);
        }
        if (runtime->udp6_v4mapped_sendmsg_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp6_v4mapped_sendmsg_prog_fd, BPF_CGROUP_UDP6_SENDMSG);
        }
        if (runtime->connect6_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect6_prog_fd, BPF_CGROUP_INET6_CONNECT);
        }
        if (runtime->connect6_v4mapped_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect6_v4mapped_prog_fd, BPF_CGROUP_INET6_CONNECT);
        }
        if (runtime->udp4_recvmsg_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp4_recvmsg_prog_fd, BPF_CGROUP_UDP4_RECVMSG);
        }
        if (runtime->udp4_sendmsg_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->udp4_sendmsg_prog_fd, BPF_CGROUP_UDP4_SENDMSG);
        }
        if (runtime->connect4_prog_fd >= 0) {
            (void)bpf2socks_bpf_prog_detach(runtime->cgroup_fd, runtime->connect4_prog_fd, BPF_CGROUP_INET4_CONNECT);
        }
    }
    (void)bpf2socks_bpf_cgroup_restore(runtime->cgroup_fd);
    bpf2socks_close_fd(&runtime->reuseport_prog_fd);
    bpf2socks_close_fd(&runtime->tc_egress_prog_fd);
    bpf2socks_close_fd(&runtime->tc_ingress_prog_fd);
    bpf2socks_close_fd(&runtime->reuseport_udp6_map_fd);
    bpf2socks_close_fd(&runtime->reuseport_tcp6_map_fd);
    bpf2socks_close_fd(&runtime->reuseport_udp4_map_fd);
    bpf2socks_close_fd(&runtime->reuseport_tcp4_map_fd);
    bpf2socks_close_fd(&runtime->tc_fragment_map_fd);
    bpf2socks_close_fd(&runtime->tc_scratch_map_fd);
    bpf2socks_close_fd(&runtime->tc_token_to_original_map_fd);
    bpf2socks_close_fd(&runtime->tc_original_to_token_map_fd);
    bpf2socks_close_fd(&runtime->tc_runtime_control_map_fd);
    bpf2socks_close_fd(&runtime->udp6_v4mapped_recvmsg_prog_fd);
    bpf2socks_close_fd(&runtime->udp6_recvmsg_prog_fd);
    bpf2socks_close_fd(&runtime->udp4_getpeername_prog_fd);
    bpf2socks_close_fd(&runtime->udp6_getpeername_prog_fd);
    bpf2socks_close_fd(&runtime->udp4_recvmsg_prog_fd);
    bpf2socks_close_fd(&runtime->udp6_v4mapped_sendmsg_prog_fd);
    bpf2socks_close_fd(&runtime->udp6_sendmsg_prog_fd);
    bpf2socks_close_fd(&runtime->udp4_sendmsg_prog_fd);
    bpf2socks_close_fd(&runtime->connect6_v4mapped_prog_fd);
    bpf2socks_close_fd(&runtime->connect6_prog_fd);
    bpf2socks_close_fd(&runtime->connect4_prog_fd);
    bpf2socks_close_fd(&runtime->udp_peer_map_fd);
    bpf2socks_close_fd(&runtime->tcp_peer_map_fd);
    bpf2socks_close_fd(&runtime->default_network_map_fd);
    bpf2socks_close_fd(&runtime->token_map_fd);
    bpf2socks_close_fd(&runtime->direct_cidr6_map_fd);
    bpf2socks_close_fd(&runtime->local_interface_cidr6_map_fd);
    bpf2socks_close_fd(&runtime->bypass_private_cidr6_map_fd);
    bpf2socks_close_fd(&runtime->proxy_cidr6_map_fd);
    bpf2socks_close_fd(&runtime->ignored_route_cidr6_map_fd);
    bpf2socks_close_fd(&runtime->ignored_route_cidr4_map_fd);
    bpf2socks_close_fd(&runtime->ignored_ifindex_map_fd);
    bpf2socks_close_fd(&runtime->direct_cidr4_map_fd);
    bpf2socks_close_fd(&runtime->local_interface_cidr4_map_fd);
    bpf2socks_close_fd(&runtime->bypass_private_cidr4_map_fd);
    bpf2socks_close_fd(&runtime->proxy_cidr4_map_fd);
    bpf2socks_close_fd(&runtime->uid_map_fd);
    bpf2socks_close_fd(&runtime->cgroup_fd);
}
