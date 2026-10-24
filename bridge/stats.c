// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bridge/stats.h"
#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/udp_budget.h"
#include "core/stop_event.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BPF2SOCKS_BRIDGE_STATS_COPY(name, json) destination->name = source->name;
#define BPF2SOCKS_BRIDGE_STATS_ADD(name, json) total->name += stats->name;
#define BPF2SOCKS_BRIDGE_STATS_SKIP(name, json)

static void copy_tcp_stats(
    struct bpf2socks_bridge_stats *destination,
    const struct bpf2socks_bridge_stats *source) {
    BPF2SOCKS_BRIDGE_STATS(BPF2SOCKS_BRIDGE_STATS_COPY, BPF2SOCKS_BRIDGE_STATS_SKIP, BPF2SOCKS_BRIDGE_STATS_SKIP)
}

static void copy_udp_stats(
    struct bpf2socks_bridge_stats *destination,
    const struct bpf2socks_bridge_stats *source) {
    BPF2SOCKS_BRIDGE_STATS(BPF2SOCKS_BRIDGE_STATS_SKIP, BPF2SOCKS_BRIDGE_STATS_COPY, BPF2SOCKS_BRIDGE_STATS_SKIP)
}

static void add_worker_stats(struct bpf2socks_bridge_stats *total, const struct bpf2socks_bridge_stats *stats) {
    BPF2SOCKS_BRIDGE_STATS(BPF2SOCKS_BRIDGE_STATS_ADD, BPF2SOCKS_BRIDGE_STATS_ADD, BPF2SOCKS_BRIDGE_STATS_SKIP)
}

struct bridge_stats_thread_args {
    struct bpf2socks_bridge_worker *workers;
    uint32_t worker_count;
    char stats_path[BPF2SOCKS_MAX_PATH_LEN];
};

void bpf2socks_bridge_publish_tcp_stats(struct bpf2socks_bridge_worker *worker) {
    if (worker == NULL || worker->config == NULL || !worker->config->debug_stats ||
        !worker->stats_snapshot_mutex_initialized) {
        return;
    }
    if (pthread_mutex_lock(&worker->stats_snapshot_mutex) != 0) return;
    copy_tcp_stats(&worker->stats_snapshot, &worker->tcp_stats);
    (void)pthread_mutex_unlock(&worker->stats_snapshot_mutex);
}

void bpf2socks_bridge_publish_udp_stats(struct bpf2socks_bridge_worker *worker) {
    if (worker == NULL || worker->config == NULL || !worker->config->debug_stats ||
        !worker->stats_snapshot_mutex_initialized) {
        return;
    }
    if (pthread_mutex_lock(&worker->stats_snapshot_mutex) != 0) return;
    copy_udp_stats(&worker->stats_snapshot, &worker->udp_stats);
    (void)pthread_mutex_unlock(&worker->stats_snapshot_mutex);
}

static void copy_stats_snapshot(
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_bridge_stats *out) {
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    if (worker == NULL || !worker->stats_snapshot_mutex_initialized) return;
    if (pthread_mutex_lock(&worker->stats_snapshot_mutex) != 0) return;
    *out = worker->stats_snapshot;
    (void)pthread_mutex_unlock(&worker->stats_snapshot_mutex);
}

static int stats_path_from_pid_path(const char *pid_path, char *out, size_t out_size) {
    if (pid_path == NULL || pid_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    int written = snprintf(out, out_size, "%s.stats", pid_path);
    if (written < 0 || (size_t)written >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static void aggregate_worker_stats(
    struct bpf2socks_bridge_worker *workers,
    uint32_t worker_count,
    struct bpf2socks_bridge_stats *out) {
    memset(out, 0, sizeof(*out));
    if (workers == NULL) return;
    for (uint32_t i = 0; i < worker_count; ++i) {
        struct bpf2socks_bridge_stats snapshot;
        copy_stats_snapshot(&workers[i], &snapshot);
        add_worker_stats(out, &snapshot);
        size_t peak = bpf2socks_udp_budget_peak(workers[i].udp_pending_budget);
        if ((uint64_t)peak > out->udp_pending_peak_bytes) {
            out->udp_pending_peak_bytes = (uint64_t)peak;
        }
    }
}

static int write_stats_snapshot(const char *path, const struct bpf2socks_bridge_stats *stats) {
    char tmp_path[BPF2SOCKS_MAX_PATH_LEN];
    int written = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (written < 0 || (size_t)written >= sizeof(tmp_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    FILE *file = fopen(tmp_path, "wb");
    if (file == NULL) return -1;
    size_t count = fwrite(stats, sizeof(*stats), 1U, file);
    int close_result = fclose(file);
    if (count != 1U || close_result != 0) {
        (void)unlink(tmp_path);
        errno = EIO;
        return -1;
    }
    if (rename(tmp_path, path) != 0) {
        (void)unlink(tmp_path);
        return -1;
    }
    return 0;
}

static void *bridge_stats_thread(void *arg) {
    struct bridge_stats_thread_args *args = arg;
    if (args == NULL) return NULL;
    while (!bpf2socks_stop_requested()) {
        struct bpf2socks_bridge_stats stats;
        aggregate_worker_stats(args->workers, args->worker_count, &stats);
        (void)write_stats_snapshot(args->stats_path, &stats);
        /* Sleep one second, but end at once when the stop event fires. */
        struct pollfd stop_poll = {.fd = bpf2socks_stop_event_fd(), .events = POLLIN};
        if (stop_poll.fd < 0 || poll(&stop_poll, 1U, 1000) < 0) sleep(1U);
    }
    struct bpf2socks_bridge_stats stats;
    aggregate_worker_stats(args->workers, args->worker_count, &stats);
    (void)write_stats_snapshot(args->stats_path, &stats);
    free(args);
    return NULL;
}

int bpf2socks_bridge_stats_start(
    const char *pid_path,
    struct bpf2socks_bridge_worker *workers,
    uint32_t worker_count,
    pthread_t *thread) {
    struct bridge_stats_thread_args *args = calloc(1U, sizeof(*args));
    if (args == NULL) return -1;
    args->workers = workers;
    args->worker_count = worker_count;
    if (stats_path_from_pid_path(pid_path, args->stats_path, sizeof(args->stats_path)) < 0) {
        free(args);
        return -1;
    }
    int rc = pthread_create(thread, NULL, bridge_stats_thread, args);
    if (rc != 0) {
        free(args);
        errno = rc;
        return -1;
    }
    return 0;
}

int bpf2socks_bridge_stats_read(const char *pid_path, struct bpf2socks_bridge_stats *out) {
    if (out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    char path[BPF2SOCKS_MAX_PATH_LEN];
    if (stats_path_from_pid_path(pid_path, path, sizeof(path)) < 0) return -1;
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return errno == ENOENT ? 0 : -1;
    }
    size_t bytes = fread(out, 1U, sizeof(*out), file);
    int read_error = ferror(file);
    int extra = fgetc(file);
    if (ferror(file) != 0) read_error = 1;
    int close_result = fclose(file);
    /* The snapshot is written by the running instance of this same binary. */
    if (bytes != sizeof(*out) || extra != EOF || read_error != 0 || close_result != 0) {
        memset(out, 0, sizeof(*out));
        errno = EIO;
        return -1;
    }
    return 0;
}

void bpf2socks_bridge_stats_print_json(const struct bpf2socks_bridge_stats *stats) {
#define BPF2SOCKS_BRIDGE_STATS_ENTRY(name, json) {json, offsetof(struct bpf2socks_bridge_stats, name)},
    static const struct {
        const char *json;
        size_t offset;
    } entries[] = {
        BPF2SOCKS_BRIDGE_STATS(BPF2SOCKS_BRIDGE_STATS_ENTRY, BPF2SOCKS_BRIDGE_STATS_ENTRY, BPF2SOCKS_BRIDGE_STATS_ENTRY)
    };
#undef BPF2SOCKS_BRIDGE_STATS_ENTRY
    putchar('{');
    for (size_t i = 0U; i < sizeof(entries) / sizeof(entries[0]); ++i) {
        uint64_t value;
        memcpy(&value, (const uint8_t *)stats + entries[i].offset, sizeof(value));
        printf("%s\"%s\":%" PRIu64, i == 0U ? "" : ",", entries[i].json, value);
    }
    printf("}\n");
}
