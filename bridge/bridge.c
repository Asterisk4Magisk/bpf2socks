// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bridge/bridge.h"
#include "bpf/reuseport.h"
#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/socks5.h"
#include "bridge/udp_budget.h"
#include "bridge/udp_relay_registry.h"
#include "core/compat.h"
#include "core/log.h"
#include "core/resource_limits.h"
#include "core/socket_util.h"
#include "core/stop_event.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct bridge_thread_args {
    struct bpf2socks_bridge_worker *worker;
    bool udp;
    int *result;
};

struct bridge_worker_threads {
    pthread_t tcp_thread;
    pthread_t udp_thread;
    bool tcp_started;
    bool udp_started;
    int tcp_result;
    int udp_result;
};

static int bind_tcp4_listener(const struct bpf2socks_runtime_config *config) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    bpf2socks_socket_tune_tcp_buffers(fd, config);
    bpf2socks_socket_enable_fastopen_listener(fd);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->listen_port);
    if (inet_pton(AF_INET, config->listen_host, &addr.sin_addr) != 1) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 4096) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int bind_tcp6_listener(const struct bpf2socks_runtime_config *config) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    bpf2socks_socket_tune_tcp_buffers(fd, config);
    bpf2socks_socket_enable_fastopen_listener(fd);
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(config->listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 4096) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int bind_udp4_listener(const struct bpf2socks_runtime_config *config) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    uint32_t udp_buffer = bpf2socks_socket_clamp_buffer(
        config->udp_socket_buffer_size,
        BPF2SOCKS_DEFAULT_UDP_SOCKET_BUFFER_SIZE);
    bpf2socks_socket_tune_buffers(fd, udp_buffer, udp_buffer);
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    (void)setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->listen_port);
    if (inet_pton(AF_INET, config->listen_host, &addr.sin_addr) != 1) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int bind_udp6_listener(const struct bpf2socks_runtime_config *config) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    uint32_t udp_buffer = bpf2socks_socket_clamp_buffer(
        config->udp_socket_buffer_size,
        BPF2SOCKS_DEFAULT_UDP_SOCKET_BUFFER_SIZE);
    bpf2socks_socket_tune_buffers(fd, udp_buffer, udp_buffer);
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof(one));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(config->listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static void *bridge_worker_thread(void *arg) {
    struct bridge_thread_args *thread_args = arg;
    if (thread_args == NULL) return NULL;
    struct bpf2socks_bridge_worker *worker = thread_args->worker;
    bool udp = thread_args->udp;
    int *result = thread_args->result;
    free(thread_args);
    *result = udp
        ? bpf2socks_bridge_udp_run(worker)
        : bpf2socks_bridge_tcp_run(worker);
    if (*result != 0) bpf2socks_stop_request();
    return NULL;
}

static int start_worker_thread(
    struct bpf2socks_bridge_worker *worker,
    bool udp,
    pthread_t *thread,
    int *result) {
    struct bridge_thread_args *args = malloc(sizeof(*args));
    if (args == NULL) return -1;
    args->worker = worker;
    args->udp = udp;
    args->result = result;
    *result = -1;
    int rc = pthread_create(thread, NULL, bridge_worker_thread, args);
    if (rc != 0) {
        free(args);
        errno = rc;
        return -1;
    }
    return 0;
}

static void close_worker_sockets(struct bpf2socks_bridge_worker *worker) {
    if (worker == NULL) return;
    if (worker->tcp4_listener_fd >= 0) {
        close(worker->tcp4_listener_fd);
        worker->tcp4_listener_fd = -1;
    }
    if (worker->tcp6_listener_fd >= 0) {
        close(worker->tcp6_listener_fd);
        worker->tcp6_listener_fd = -1;
    }
    if (worker->udp4_listener_fd >= 0) {
        close(worker->udp4_listener_fd);
        worker->udp4_listener_fd = -1;
    }
    if (worker->udp6_listener_fd >= 0) {
        close(worker->udp6_listener_fd);
        worker->udp6_listener_fd = -1;
    }
}

static void close_workers(struct bpf2socks_bridge_worker *workers, uint32_t worker_count) {
    if (workers == NULL) return;
    for (uint32_t i = 0; i < worker_count; ++i) {
        close_worker_sockets(&workers[i]);
    }
}

static void destroy_worker_stats_snapshot_mutexes(
    struct bpf2socks_bridge_worker *workers,
    uint32_t worker_count) {
    if (workers == NULL) return;
    for (uint32_t i = 0; i < worker_count; ++i) {
        if (!workers[i].stats_snapshot_mutex_initialized) continue;
        (void)pthread_mutex_destroy(&workers[i].stats_snapshot_mutex);
        workers[i].stats_snapshot_mutex_initialized = false;
    }
}

static bool pid_file_enabled(const char *pid_path) {
    return pid_path != NULL && pid_path[0] != '\0' && strcmp(pid_path, "/dev/null") != 0;
}

static int write_pid_file(const char *pid_path) {
    FILE *file = fopen(pid_path, "w");
    if (file == NULL) return -1;
    int write_result = fprintf(file, "%ld\n", (long)getpid());
    int saved_errno = write_result < 0 ? errno : 0;
    int close_result = fclose(file);
    if (close_result != 0 && saved_errno == 0) saved_errno = errno;
    if (write_result < 0 || close_result != 0) {
        (void)unlink(pid_path);
        errno = saved_errno != 0 ? saved_errno : EIO;
        return -1;
    }
    return 0;
}

/* Zeroed and cache-line aligned, so per-thread statistics stay on their own lines. */
static struct bpf2socks_bridge_worker *alloc_workers(uint32_t worker_count) {
    void *memory = NULL;
    size_t size = (size_t)worker_count * sizeof(struct bpf2socks_bridge_worker);
    if (posix_memalign(&memory, _Alignof(struct bpf2socks_bridge_worker), size) != 0) return NULL;
    memset(memory, 0, size);
    return memory;
}

int bpf2socks_bridge_run(const struct bpf2socks_runtime_config *config, const char *pid_path) {
    if (config == NULL || config->worker_count == 0U || config->worker_count > BPF2SOCKS_MAX_WORKER_COUNT) {
        errno = EINVAL;
        return -1;
    }
    uint32_t worker_count = config->worker_count;
    struct bpf2socks_udp_budget udp_pending_budget;
    bpf2socks_udp_budget_init(&udp_pending_budget, config->max_udp_pending_bytes);
    struct bpf2socks_tcp_budget tcp_session_budget;
    tcp_session_budget.cap = config->max_tcp_sessions;
    atomic_init(&tcp_session_budget.used, 0U);
    struct sockaddr_storage socks_addr;
    socklen_t socks_addr_len = 0;
    if (bpf2socks_socks5_resolve_server(config->socks_host, config->socks_port, &socks_addr, &socks_addr_len) < 0) {
        return -1;
    }
    struct bpf2socks_bridge_worker *workers = alloc_workers(worker_count);
    struct bridge_worker_threads *threads = calloc(worker_count, sizeof(*threads));
    struct bpf2socks_udp_relay_registry *udp_relay_registry = calloc(1U, sizeof(*udp_relay_registry));
    if (workers == NULL || threads == NULL || udp_relay_registry == NULL) {
        free(workers);
        free(threads);
        free(udp_relay_registry);
        return -1;
    }

    int result = -1;
    pthread_t stats_thread;
    bool stats_started = false;
    bool pid_file_written = false;
    for (uint32_t i = 0; i < worker_count; ++i) {
        workers[i].id = i;
        workers[i].tcp4_listener_fd = -1;
        workers[i].tcp6_listener_fd = -1;
        workers[i].udp4_listener_fd = -1;
        workers[i].udp6_listener_fd = -1;
        workers[i].epoll_fd = -1;
        workers[i].socks_addr = socks_addr;
        workers[i].socks_addr_len = socks_addr_len;
        workers[i].config = config;
        workers[i].tcp_session_budget = &tcp_session_budget;
        workers[i].udp_session_cap = bpf2socks_limits_worker_quota(config->max_udp_sessions, i, worker_count);
        workers[i].udp_binding_cap = bpf2socks_limits_worker_quota(config->max_udp_bindings, i, worker_count);
        workers[i].udp_pending_budget = &udp_pending_budget;
        workers[i].udp_relay_registry = udp_relay_registry;
        int mutex_result = pthread_mutex_init(&workers[i].stats_snapshot_mutex, NULL);
        if (mutex_result != 0) {
            errno = mutex_result;
            bpf2socks_stop_request();
            goto done;
        }
        workers[i].stats_snapshot_mutex_initialized = true;

        workers[i].udp4_listener_fd = bind_udp4_listener(config);
        if (workers[i].udp4_listener_fd < 0) {
            bpf2socks_log("failed to bind UDP4 listener for worker %u: errno=%d", i, errno);
            bpf2socks_stop_request();
            goto done;
        }

        if (config->enable_ipv6 || config->enable_dns_hijack) {
            workers[i].udp6_listener_fd = bind_udp6_listener(config);
            if (workers[i].udp6_listener_fd < 0) {
                bpf2socks_log("failed to bind UDP6 listener for worker %u: errno=%d", i, errno);
                bpf2socks_stop_request();
                goto done;
            }
        }

        workers[i].tcp4_listener_fd = bind_tcp4_listener(config);
        if (workers[i].tcp4_listener_fd < 0) {
            bpf2socks_log("failed to bind TCP4 listener for worker %u: errno=%d", i, errno);
            bpf2socks_stop_request();
            goto done;
        }

        if (config->enable_ipv6 || config->enable_dns_hijack) {
            workers[i].tcp6_listener_fd = bind_tcp6_listener(config);
            if (workers[i].tcp6_listener_fd < 0) {
                bpf2socks_log("failed to bind TCP6 listener for worker %u: errno=%d", i, errno);
                bpf2socks_stop_request();
                goto done;
            }
        }

        if (bpf2socks_reuseport_register_worker(
                config,
                workers[i].id,
                workers[i].tcp4_listener_fd,
                workers[i].udp4_listener_fd,
                workers[i].tcp6_listener_fd,
                workers[i].udp6_listener_fd) < 0) {
            bpf2socks_log("failed to register reuseport sockets for worker %u: errno=%d", i, errno);
            bpf2socks_stop_request();
            goto done;
        }
    }

    if (config->debug_stats && pid_file_enabled(pid_path) &&
        bpf2socks_bridge_stats_start(pid_path, workers, worker_count, &stats_thread) == 0) {
        stats_started = true;
    }

    for (uint32_t i = 0; i < worker_count; ++i) {
        if (start_worker_thread(
                &workers[i], false, &threads[i].tcp_thread, &threads[i].tcp_result) == 0) {
            threads[i].tcp_started = true;
        } else {
            bpf2socks_log("failed to start TCP worker %u: errno=%d", i, errno);
            bpf2socks_stop_request();
            goto done;
        }
        if (start_worker_thread(
                &workers[i], true, &threads[i].udp_thread, &threads[i].udp_result) == 0) {
            threads[i].udp_started = true;
        } else {
            bpf2socks_log("failed to start UDP worker %u: errno=%d", i, errno);
            bpf2socks_stop_request();
            goto done;
        }
    }

    if (pid_file_enabled(pid_path)) {
        if (write_pid_file(pid_path) < 0) {
            bpf2socks_log("failed to write PID file: errno=%d", errno);
            bpf2socks_stop_request();
            goto done;
        }
        pid_file_written = true;
    }

    result = 0;

done:
    for (uint32_t i = 0; i < worker_count; ++i) {
        if (threads[i].tcp_started) {
            pthread_join(threads[i].tcp_thread, NULL);
            if (threads[i].tcp_result != 0) result = -1;
        }
    }
    bpf2socks_stop_request();
    for (uint32_t i = 0; i < worker_count; ++i) {
        if (threads[i].udp_started) {
            pthread_join(threads[i].udp_thread, NULL);
            if (threads[i].udp_result != 0) result = -1;
        }
    }
    if (stats_started) pthread_join(stats_thread, NULL);
    close_workers(workers, worker_count);
    destroy_worker_stats_snapshot_mutexes(workers, worker_count);
    free(threads);
    free(workers);
    free(udp_relay_registry);
    if (pid_file_written) (void)unlink(pid_path);
    return result;
}
