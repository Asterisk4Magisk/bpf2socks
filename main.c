// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf/runtime.h"
#include "bpf/syscall.h"
#include "bpf2socks.h"
#include "bridge/bridge.h"
#include "bridge/stats.h"
#include "bridge/udp_destroy_events.h"
#include "core/config.h"
#include "core/json.h"
#include "core/log.h"
#include "core/probe.h"
#include "core/resource_limits.h"
#include "core/stop_event.h"
#include "kern/tc_token.h"
#include "shared/bpf_cgroup_owned.h"

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
/* --stop waits up to 10 s for the instance to finish its own cleanup. */
#define BPF2SOCKS_STOP_WAIT_ATTEMPTS 200U
#define BPF2SOCKS_STOP_WAIT_STEP_MICROSECONDS 50000U

static bool dns_enhancement_requested;

static void on_signal(int signo) {
    (void)signo;
    bpf2socks_stop_request();
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
        if (bpf2socks_config_load(path, dns_enhancement_requested, &config, &policy) < 0) {
            print_probe_json(false, "invalid bpf2socks config", false, false, false, false);
            return 1;
        }
    } else {
        bpf2socks_config_defaults(&config, &policy);
        config.listen_port = 65532U;
    }

    bool hotspot_policy = policy.hotspot_interface_prefix_count > 0U;
    if (bpf2socks_probe_splice(message, sizeof(message)) < 0) {
        print_probe_json(false, message, false, false, false, hotspot_policy);
        return 1;
    }
    if (bpf2socks_probe_tcp_options(message, sizeof(message)) < 0) {
        print_probe_json(false, message, true, false, false, hotspot_policy);
        return 1;
    }
    char detail[192];
    if (bpf2socks_udp_destroy_events_probe(detail, sizeof(detail)) < 0) {
        snprintf(message, sizeof(message), "UDP socket destroy notifications are unavailable: %s", detail);
        print_probe_json(false, message, true, true, false, hotspot_policy);
        return 1;
    }
    if (bpf2socks_limits_raise_memlock() < 0) {
        snprintf(message, sizeof(message), "failed to raise memlock limit: errno=%d", errno);
        print_probe_json(false, message, true, true, false, hotspot_policy);
        return 1;
    }
    if (bpf2socks_bpf_runtime_probe(&config, &policy, message, sizeof(message)) == 0) {
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
    if (asterisk_cgroup_reconcile(config->cgroup_path, config->pinned_object_dir) != 0) return;
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
    uint64_t per_worker = BPF2SOCKS_FD_PER_WORKER_TCP + BPF2SOCKS_FD_PER_WORKER_UDP +
        4ULL * BPF2SOCKS_TCP_PIPE_POOL_CAP;
    if (config->enable_ipv6 || config->enable_dns_hijack) {
        per_worker += BPF2SOCKS_FD_PER_WORKER_TCP_IPV6;
        per_worker += BPF2SOCKS_FD_PER_WORKER_UDP_IPV6;
    }
    return BPF2SOCKS_FD_RUNTIME_RESERVE + BPF2SOCKS_FD_SAFETY_MARGIN + per_worker * worker_count;
}

static int apply_nofile_session_capacity(struct bpf2socks_runtime_config *config) {
    if (config == NULL) {
        errno = EINVAL;
        return -1;
    }
    uint64_t nofile_limit = 0U;
    uint64_t open_fds = 0U;
    if (bpf2socks_limits_nofile_soft(&nofile_limit) < 0 || current_open_fd_count(&open_fds) < 0) {
        return -1;
    }
    struct bpf2socks_limits_capacity requested = {
        .worker_count = config->worker_count,
        .max_tcp_sessions = config->max_tcp_sessions,
        .max_udp_sessions = config->max_udp_sessions,
        .max_udp_bindings = config->max_udp_bindings,
    };
    for (uint32_t worker_count = requested.worker_count; worker_count > 0U; --worker_count) {
        struct bpf2socks_limits_capacity effective = requested;
        effective.worker_count = worker_count;
        uint64_t reserve_fds = open_fds + static_fd_reserve(config, worker_count);
        if (bpf2socks_limits_fit_session_capacity(
                nofile_limit,
                reserve_fds,
                &effective) != 0) {
            continue;
        }
        config->worker_count = effective.worker_count;
        config->max_tcp_sessions = effective.max_tcp_sessions;
        config->max_udp_sessions = effective.max_udp_sessions;
        config->max_udp_bindings = effective.max_udp_bindings;
        bpf2socks_log("capacity: nofile=%" PRIu64 " open=%" PRIu64 " reserve=%" PRIu64
            " workers=%u tcp=%u udp=%u bindings=%u",
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
    if (bpf2socks_config_load(path, dns_enhancement_requested, &config, &policy) < 0) return 2;
    if (bpf2socks_limits_raise_memlock() != 0) {
        bpf2socks_log("failed to raise memlock limit: errno=%d", errno);
        return 1;
    }
    if (bpf2socks_limits_raise_nofile(BPF2SOCKS_DEFAULT_NOFILE_LIMIT) != 0) {
        bpf2socks_log("failed to raise file descriptor limit: errno=%d", errno);
    }
    if (apply_nofile_session_capacity(&config) < 0) {
        bpf2socks_log("insufficient file descriptor capacity for sessions: errno=%d", errno);
        return 1;
    }

    char message[256];
    if (bpf2socks_probe_splice(message, sizeof(message)) < 0) {
        bpf2socks_log("splice relay is unavailable: %s", message);
        return 1;
    }
    if (bpf2socks_probe_tcp_options(message, sizeof(message)) < 0) {
        bpf2socks_log("TCP socket options are unavailable: %s", message);
        return 1;
    }
    if (bpf2socks_udp_destroy_events_probe(message, sizeof(message)) < 0) {
        bpf2socks_log("UDP socket destroy notifications are unavailable: %s", message);
        return 1;
    }

    struct bpf2socks_bpf_runtime runtime;
    if (bpf2socks_bpf_runtime_start(&config, &policy, &runtime) < 0) {
        int saved_errno = errno;
        cleanup_fixed_bpf_pins(&config);
        errno = saved_errno;
        bpf2socks_log("failed to start BPF runtime: errno=%d", errno);
        return 1;
    }
    if (bpf2socks_stop_event_init() < 0) {
        int saved_errno = errno;
        bpf2socks_bpf_runtime_stop(&runtime);
        cleanup_fixed_bpf_pins(&config);
        errno = saved_errno;
        bpf2socks_log("failed to create stop event: errno=%d", errno);
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
        bpf2socks_bpf_map_lookup(runtime.tc_runtime_control_map_fd, &control_key, &control) == 0) {
        control.enabled = 0U;
        (void)bpf2socks_bpf_map_update(runtime.tc_runtime_control_map_fd, &control_key, &control);
    }
    bpf2socks_bpf_runtime_stop(&runtime);
    bpf2socks_stop_event_close();
    cleanup_fixed_bpf_pins(&config);
    return result == 0 ? 0 : 1;
}

static bool pid_path_disabled(const char *pid_path) {
    return strcmp(pid_path, "/dev/null") == 0;
}

static int start_with_config(const char *path, const char *pid_path) {
    /*
     * "--pid /dev/null" means the caller supervises this process and owns
     * single-instance exclusion, so no "/dev/null.lock" is created in /dev.
     */
    if (pid_path_disabled(pid_path)) return start_with_config_unlocked(path, pid_path);
    char lock_path[BPF2SOCKS_MAX_PATH_LEN];
    int written = snprintf(lock_path, sizeof(lock_path), "%s.lock", pid_path);
    if (written < 0 || (size_t)written >= sizeof(lock_path)) {
        errno = ENAMETOOLONG;
        bpf2socks_log("instance lock path is too long");
        return 1;
    }
    int lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd < 0) {
        bpf2socks_log("failed to open instance lock: errno=%d", errno);
        return 1;
    }
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        int saved_errno = errno;
        close(lock_fd);
        errno = saved_errno;
        bpf2socks_log("already running for this PID path: errno=%d", errno);
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

/*
 * A running instance holds "<pid>.lock" for its whole life. A free lock means
 * the PID file is stale and its PID may belong to another process, so nothing
 * is signalled. Otherwise wait until the instance releases the lock, so the
 * caller's cleanup never races the instance's own BPF restoration.
 */
static void stop_running_instance(const char *pid_path) {
    char lock_path[BPF2SOCKS_MAX_PATH_LEN];
    int written = snprintf(lock_path, sizeof(lock_path), "%s.lock", pid_path);
    if (written < 0 || (size_t)written >= sizeof(lock_path)) return;
    int lock_fd = open(lock_path, O_RDWR | O_CLOEXEC);
    if (lock_fd < 0) return;
    if (flock(lock_fd, LOCK_EX | LOCK_NB) == 0) {
        close(lock_fd);
        return;
    }
    FILE *file = fopen(pid_path, "r");
    if (file != NULL) {
        long pid = 0;
        if (fscanf(file, "%ld", &pid) == 1 && pid > 1L) {
            (void)kill((pid_t)pid, SIGTERM);
        }
        fclose(file);
    }
    for (unsigned int attempt = 0U; attempt < BPF2SOCKS_STOP_WAIT_ATTEMPTS; ++attempt) {
        if (flock(lock_fd, LOCK_EX | LOCK_NB) == 0) break;
        (void)usleep(BPF2SOCKS_STOP_WAIT_STEP_MICROSECONDS);
    }
    close(lock_fd);
}

static int stop_with_config(const char *path, const char *pid_path) {
    struct bpf2socks_runtime_config config;
    struct bpf2socks_policy_config policy;
    if (bpf2socks_config_load(path, dns_enhancement_requested, &config, &policy) < 0) return 0;
    if (!pid_path_disabled(pid_path)) stop_running_instance(pid_path);
    if (asterisk_cgroup_reconcile(config.cgroup_path, config.pinned_object_dir) != 0) return 1;
    bpf2socks_udp6_recovery_cleanup();
    cleanup_fixed_bpf_pins(&config);
    return 0;
}

static int stats_with_pid(const char *pid_path) {
    struct bpf2socks_bridge_stats stats;
    if (bpf2socks_bridge_stats_read(pid_path, &stats) < 0) {
        bpf2socks_log("failed to read bridge stats: errno=%d", errno);
        return 1;
    }
    bpf2socks_bridge_stats_print_json(&stats);
    return 0;
}

int main(int argc, char **argv) {
    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--dns-enhancement") == 0) dns_enhancement_requested = true;
    }
    if (argc >= 2 && strcmp(argv[1], "--probe") == 0) {
        return probe_with_config(config_path_arg(argc, argv));
    }
    if (argc >= 2 && strcmp(argv[1], "--start") == 0) {
        const char *path = config_path_arg(argc, argv);
        const char *pid_path = pid_path_arg(argc, argv);
        if (path == NULL || pid_path == NULL) {
            bpf2socks_log("--start requires --config FILE --pid FILE");
            return 2;
        }
        return start_with_config(path, pid_path);
    }
    if (argc >= 2 && strcmp(argv[1], "--stop") == 0) {
        const char *path = config_path_arg(argc, argv);
        const char *pid_path = pid_path_arg(argc, argv);
        if (path == NULL || pid_path == NULL) {
            bpf2socks_log("--stop requires --config FILE --pid FILE");
            return 2;
        }
        return stop_with_config(path, pid_path);
    }
    if (argc >= 2 && strcmp(argv[1], "--stats") == 0) {
        const char *pid_path = pid_path_arg(argc, argv);
        if (pid_path == NULL) {
            bpf2socks_log("--stats requires --pid FILE");
            return 2;
        }
        return stats_with_pid(pid_path);
    }
    bpf2socks_log("usage: %s --probe [--config FILE] | --start --config FILE --pid FILE | --stop --config FILE --pid FILE | --stats --pid FILE", argv[0]);
    return 2;
}
