// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf/syscall.h"
#include "bpf2socks.h"
#include "core/log.h"

#include <linux/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16
#endif

#define BPF2SOCKS_LOG_BUF_SIZE 65536U

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#elif defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#endif
#endif

static long bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

int bpf2socks_bpf_map_create(enum bpf_map_type type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, uint32_t flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = flags;
    return (int)bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf2socks_bpf_map_update(int map_fd, const void *key, const void *value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    attr.flags = BPF_ANY;
    return (int)bpf_sys(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf2socks_bpf_map_lookup(int map_fd, const void *key, void *value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    return (int)bpf_sys(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf2socks_bpf_map_next_key(int map_fd, const void *key, void *next_key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.next_key = (uint64_t)(uintptr_t)next_key;
    return (int)bpf_sys(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

int bpf2socks_bpf_map_lookup_and_delete(int map_fd, const void *key, void *value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    return (int)bpf_sys(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf2socks_bpf_map_delete(int map_fd, const void *key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    return (int)bpf_sys(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static void mkdir_p(const char *path) {
    if (path == NULL || path[0] == '\0') return;
    char current[BPF2SOCKS_MAX_PATH_LEN];
    snprintf(current, sizeof(current), "%s", path);
    for (char *cursor = current + 1; *cursor != '\0'; ++cursor) {
        if (*cursor != '/') continue;
        *cursor = '\0';
        (void)mkdir(current, 0700);
        *cursor = '/';
    }
    (void)mkdir(current, 0700);
}

int bpf2socks_bpf_obj_pin(int fd, const char *path) {
    if (fd < 0 || path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    char parent[BPF2SOCKS_MAX_PATH_LEN];
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash != NULL) {
        *slash = '\0';
        if (parent[0] != '\0') {
            mkdir_p(parent);
        }
    }
    (void)unlink(path);
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    attr.bpf_fd = (uint32_t)fd;
    return (int)bpf_sys(BPF_OBJ_PIN, &attr, sizeof(attr));
}

static int load_prog_with_retry(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type,
    char *log_buf,
    uint32_t log_size,
    uint32_t log_level) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insns = (uint64_t)(uintptr_t)insns;
    attr.insn_cnt = (uint32_t)insn_count;
    attr.license = (uint64_t)(uintptr_t)"GPL";
    attr.expected_attach_type = expected_attach_type;
    attr.log_buf = log_level != 0U ? (uint64_t)(uintptr_t)log_buf : 0U;
    attr.log_size = log_level != 0U ? log_size : 0U;
    attr.log_level = log_level;
    if (name != NULL) {
        snprintf(attr.prog_name, BPF_OBJ_NAME_LEN, "%s", name);
    }
    /* Like libbpf, retry only the verifier's transient EAGAIN. Keep this
     * bounded; permanent verifier/resource failures must fail startup. */
    int fd;
    unsigned retries = 5U;
    do {
        fd = (int)bpf_sys(BPF_PROG_LOAD, &attr, sizeof(attr));
    } while (fd < 0 && errno == EAGAIN && retries-- > 0U);
    return fd;
}

static int retry_without_verifier_log(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type) {
    return load_prog_with_retry(insns, insn_count, name, prog_type, expected_attach_type, NULL, 0U, 0U);
}

/* Each verifier line becomes its own prefixed log line. */
static void log_verifier_output(char *output) {
    for (char *line = output; line != NULL && *line != '\0';) {
        char *end = strchr(line, '\n');
        if (end != NULL) *end = '\0';
        if (*line != '\0') bpf2socks_log("verifier: %s", line);
        line = end != NULL ? end + 1 : NULL;
    }
}

int bpf2socks_bpf_prog_load(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type,
    bool log_error) {
    static char log_buf[BPF2SOCKS_LOG_BUF_SIZE];
    memset(log_buf, 0, sizeof(log_buf));
    uint32_t log_level = log_error ? 1U : 0U;
    int fd = load_prog_with_retry(
        insns,
        insn_count,
        name,
        prog_type,
        expected_attach_type,
        log_buf,
        sizeof(log_buf),
        log_level);
    if (fd < 0 && log_error && errno == ENOSPC) {
        fd = retry_without_verifier_log(
            insns,
            insn_count,
            name,
            prog_type,
            expected_attach_type);
        if (fd >= 0) return fd;
    }
    if (fd < 0 && log_error) {
        int load_errno = errno;
        bpf2socks_log("%s load failed: errno=%d (%s)",
            name == NULL ? "BPF program" : name,
            load_errno,
            strerror(load_errno));
        log_verifier_output(log_buf);
        errno = load_errno;
    }
    return fd;
}

// Attach/detach run serially on the helper's lifecycle thread. Keep references
// only in this process; never adopt another process's saved recovery state.
struct exclusive_attachment {
    bool active;
    int cgroup_fd;
    int prog_fd;
    int original_fd;
    enum bpf_attach_type type;
};

static struct exclusive_attachment exclusive_attachments[6];

static bool exclusive_hook(enum bpf_attach_type type) {
    return type == BPF_CGROUP_INET4_CONNECT || type == BPF_CGROUP_INET6_CONNECT ||
        type == BPF_CGROUP_UDP4_SENDMSG || type == BPF_CGROUP_UDP6_SENDMSG ||
        type == BPF_CGROUP_UDP4_RECVMSG || type == BPF_CGROUP_UDP6_RECVMSG;
}

static int query_exclusive(int cgroup_fd, enum bpf_attach_type type, uint32_t *id) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.query.target_fd = (uint32_t)cgroup_fd;
    attr.query.attach_type = type;
    attr.query.prog_cnt = 1;
    attr.query.prog_ids = (uintptr_t)id;
    if (bpf_sys(BPF_PROG_QUERY, &attr, sizeof(attr)) < 0) return -1;
    if (attr.query.attach_flags != 0 || attr.query.prog_cnt != 1 || *id == 0) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

static bool unconditional_allow(int fd, uint32_t id) {
    const struct bpf_insn expected[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .imm = 1},
        {.code = BPF_JMP | BPF_EXIT}
    };
    struct bpf_insn instructions[2];
    memset(instructions, 0, sizeof(instructions));
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    info.xlated_prog_len = sizeof(instructions);
    info.xlated_prog_insns = (uintptr_t)instructions;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uintptr_t)&info;
    return bpf_sys(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0 &&
        info.id == id && info.type == BPF_PROG_TYPE_CGROUP_SOCK_ADDR &&
        info.xlated_prog_len == sizeof(expected) &&
        memcmp(instructions, expected, sizeof(expected)) == 0;
}

static int attach_with_flags(int cgroup_fd, int prog_fd, enum bpf_attach_type type, uint32_t flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = (uint32_t)cgroup_fd;
    attr.attach_bpf_fd = (uint32_t)prog_fd;
    attr.attach_type = type;
    attr.attach_flags = flags;
    return (int)bpf_sys(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

int bpf2socks_bpf_prog_attach(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type) {
    if (attach_with_flags(cgroup_fd, prog_fd, attach_type, BPF_F_ALLOW_MULTI) == 0) return 0;
    int saved = errno;
    if ((saved != EPERM && saved != EINVAL && saved != EBUSY) || !exclusive_hook(attach_type)) return -1;
    struct exclusive_attachment *slot = NULL;
    for (size_t i = 0; i < sizeof(exclusive_attachments) / sizeof(exclusive_attachments[0]); ++i) {
        struct exclusive_attachment *entry = &exclusive_attachments[i];
        if (entry->active && entry->cgroup_fd == cgroup_fd && entry->type == attach_type) {
            errno = EBUSY;
            return -1;
        }
        if (!entry->active) slot = entry;
    }
    uint32_t id = 0;
    if (slot == NULL || query_exclusive(cgroup_fd, attach_type, &id) < 0) goto conflict;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = id;
    int original = (int)bpf_sys(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
    if (original < 0) goto conflict;
    uint32_t checked_id = 0;
    if (!unconditional_allow(original, id) ||
        query_exclusive(cgroup_fd, attach_type, &checked_id) < 0 || checked_id != id) {
        close(original);
        goto conflict;
    }
    // Exclusive hooks have no compare-and-swap API on these kernels. Recheck
    // immediately before replacing; concurrent system reattachment remains a
    // kernel limitation, not something a process-local lock can prevent.
    if (attach_with_flags(cgroup_fd, prog_fd, attach_type, 0) < 0) {
        saved = errno;
        close(original);
        errno = saved;
        return -1;
    }
    *slot = (struct exclusive_attachment){true, cgroup_fd, prog_fd, original, attach_type};
    bpf2socks_log("BPF hook %u temporarily replaced verified allow-only program id=%u",
        (unsigned)attach_type, id);
    return 0;

conflict:
    bpf2socks_log("BPF hook %u conflict: exclusive program is not a verified allow-only placeholder; preserved",
        (unsigned)attach_type);
    errno = saved;
    return -1;
}

int bpf2socks_bpf_prog_detach(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type) {
    if (cgroup_fd < 0 || prog_fd < 0) {
        errno = EBADF;
        return -1;
    }

    struct bpf_prog_info info;
    union bpf_attr attr;
    memset(&info, 0, sizeof(info));
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)prog_fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uintptr_t)&info;
    if (bpf_sys(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) != 0) return -1;
    if (info.id == 0 || info.type != BPF_PROG_TYPE_CGROUP_SOCK_ADDR) {
        errno = EINVAL;
        return -1;
    }

    uint32_t ids[64];
    memset(&attr, 0, sizeof(attr));
    attr.query.target_fd = (uint32_t)cgroup_fd;
    attr.query.attach_type = attach_type;
    attr.query.prog_cnt = sizeof(ids) / sizeof(ids[0]);
    attr.query.prog_ids = (uintptr_t)ids;
    if (bpf_sys(BPF_PROG_QUERY, &attr, sizeof(attr)) != 0) return -1;
    if (attr.query.prog_cnt > sizeof(ids) / sizeof(ids[0])) {
        errno = E2BIG;
        return -1;
    }
    int attached = 0;
    for (uint32_t i = 0; i < attr.query.prog_cnt; ++i) {
        if (ids[i] == info.id) attached = 1;
    }
    for (size_t i = 0; i < sizeof(exclusive_attachments) / sizeof(exclusive_attachments[0]); ++i) {
        struct exclusive_attachment *entry = &exclusive_attachments[i];
        if (!entry->active || entry->cgroup_fd != cgroup_fd || entry->prog_fd != prog_fd ||
            entry->type != attach_type) continue;
        if (!attached || attr.query.prog_cnt != 1 || attr.query.attach_flags != 0) {
            bpf2socks_log("BPF hook %u restoration skipped: attachment changed externally", (unsigned)attach_type);
            close(entry->original_fd);
            entry->active = false;
            errno = EBUSY;
            return -1;
        }
        // Restore directly, without first leaving the hook empty.
        if (attach_with_flags(cgroup_fd, entry->original_fd, attach_type, 0) < 0) {
            int saved = errno;
            bpf2socks_log("BPF hook %u restoration failed: errno=%d", (unsigned)attach_type, saved);
            errno = saved;
            return -1;
        }
        close(entry->original_fd);
        entry->active = false;
        return 0;
    }
    if (!attached) return 0;

    // Exclusive/OVERRIDE detach can ignore attach_bpf_fd. A loaded FD alone
    // is not attachment authority, especially during failed-start rollback.
    if (attr.query.attach_flags != BPF_F_ALLOW_MULTI) {
        errno = EPERM;
        return -1;
    }
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = (uint32_t)cgroup_fd;
    attr.attach_bpf_fd = (uint32_t)prog_fd;
    attr.attach_type = attach_type;
    return (int)bpf_sys(BPF_PROG_DETACH, &attr, sizeof(attr));
}

// Best-effort lifecycle cleanup, while both the cgroup and owned program FDs are
// still open. Retry pending restoration once and release all saved references.
int bpf2socks_bpf_cgroup_restore(int cgroup_fd) {
    int result = 0;
    for (size_t i = 0; i < sizeof(exclusive_attachments) / sizeof(exclusive_attachments[0]); ++i) {
        struct exclusive_attachment *entry = &exclusive_attachments[i];
        if (!entry->active || entry->cgroup_fd != cgroup_fd) continue;
        if (bpf2socks_bpf_prog_detach(cgroup_fd, entry->prog_fd, entry->type) < 0) {
            bpf2socks_log("BPF hook %u final restoration failed: errno=%d", (unsigned)entry->type, errno);
            result = -1;
        }
        if (entry->active) {
            close(entry->original_fd);
            entry->active = false;
        }
    }
    return result;
}
