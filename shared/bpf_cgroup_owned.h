// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
// Shared fixed cgroup program contract; keep byte-identical in bpf2socks/asteriskd.

#ifndef ASTERISK_BPF_CGROUP_OWNED_H
#define ASTERISK_BPF_CGROUP_OWNED_H

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ASTERISK_CGROUP_PATH_MAX 512U
#define ASTERISK_CGROUP_QUERY_MAX 64U

/* Every cgroup program bpf2socks attaches: its pin leaf and kernel program name. */
struct asterisk_cgroup_program {
    const char *pin;
    const char *name;
    unsigned type;
};

static const struct asterisk_cgroup_program asterisk_cgroup_programs[] = {
    {"cgroup_connect4", "b2s_conn4", BPF_CGROUP_INET4_CONNECT},
    {"cgroup_sendmsg4", "b2s_udp4", BPF_CGROUP_UDP4_SENDMSG},
    {"cgroup_recvmsg4", "b2s_urcv4", BPF_CGROUP_UDP4_RECVMSG},
    {"cgroup_connect6", "b2s_conn6", BPF_CGROUP_INET6_CONNECT},
    {"cgroup_sendmsg6", "b2s_udp6", BPF_CGROUP_UDP6_SENDMSG},
    {"cgroup_recvmsg6", "b2s_urcv6", BPF_CGROUP_UDP6_RECVMSG},
    {"cgroup_connect6_mapped", "b2s_c6v4m", BPF_CGROUP_INET6_CONNECT},
    {"cgroup_sendmsg6_mapped", "b2s_u6v4m", BPF_CGROUP_UDP6_SENDMSG},
    {"cgroup_recvmsg6_mapped", "b2s_ur6v4m", BPF_CGROUP_UDP6_RECVMSG},
    {"cgroup_peer_cap4", "b2s_ppeer4", BPF_CGROUP_INET4_GETPEERNAME},
    {"cgroup_peer_cap6", "b2s_ppeer6", BPF_CGROUP_INET6_GETPEERNAME},
    {"cgroup_peer4", "b2s_upeer4", BPF_CGROUP_INET4_GETPEERNAME},
    {"cgroup_peer6", "b2s_upeer6", BPF_CGROUP_INET6_GETPEERNAME},
};

#define ASTERISK_CGROUP_PROGRAM_COUNT (sizeof(asterisk_cgroup_programs) / sizeof(asterisk_cgroup_programs[0]))

static inline int asterisk_cgroup_sys(enum bpf_cmd command, union bpf_attr *attr) {
    return (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
}

static inline int asterisk_cgroup_info(int fd, struct bpf_prog_info *info) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    memset(info, 0, sizeof(*info));
    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = (uintptr_t)info;
    return asterisk_cgroup_sys(BPF_OBJ_GET_INFO_BY_FD, &attr);
}

static inline int asterisk_cgroup_path(char *out, size_t size, const char *root, const char *name) {
    int written = snprintf(out, size, "%s/%s", root, name);
    if (written < 0 || (size_t)written >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/*
 * Pin before attach, so abrupt helper death cannot destroy cleanup authority.
 * Never overwrite a pin: the supervisor reconciles the fixed catalog first.
 */
static inline int asterisk_cgroup_pin(int fd, const char *root) {
    struct bpf_prog_info info;
    if (asterisk_cgroup_info(fd, &info) != 0) return -1;
    for (size_t i = 0U; i < ASTERISK_CGROUP_PROGRAM_COUNT; ++i) {
        const struct asterisk_cgroup_program *program = &asterisk_cgroup_programs[i];
        if (info.type != BPF_PROG_TYPE_CGROUP_SOCK_ADDR || strcmp(info.name, program->name) != 0) continue;
        char path[ASTERISK_CGROUP_PATH_MAX];
        if (asterisk_cgroup_path(path, sizeof(path), root, program->pin) != 0) return -1;
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.pathname = (uintptr_t)path;
        attr.bpf_fd = (uint32_t)fd;
        return asterisk_cgroup_sys(BPF_OBJ_PIN, &attr);
    }
    errno = EINVAL;
    return -1;
}

/* 1 when program id is attached to the cgroup hook, 0 when not, -1 on error. */
static inline int asterisk_cgroup_has_id(int cgroup, unsigned type, uint32_t id) {
    uint32_t ids[ASTERISK_CGROUP_QUERY_MAX];
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.query.target_fd = (uint32_t)cgroup;
    attr.query.attach_type = type;
    attr.query.prog_cnt = ASTERISK_CGROUP_QUERY_MAX;
    attr.query.prog_ids = (uintptr_t)ids;
    if (asterisk_cgroup_sys(BPF_PROG_QUERY, &attr) != 0) return -1;
    if (attr.query.prog_cnt > ASTERISK_CGROUP_QUERY_MAX) {
        errno = E2BIG;
        return -1;
    }
    for (uint32_t i = 0U; i < attr.query.prog_cnt; ++i) {
        if (ids[i] != id) continue;
        /* Exclusive detach may ignore the program FD. Never use that operation. */
        if (attr.query.attach_flags != BPF_F_ALLOW_MULTI) {
            errno = EPERM;
            return -1;
        }
        return 1;
    }
    return 0;
}

/*
 * Only the object opened from the fixed pin is authority. Names alone, program
 * enumeration, saved config and telemetry never grant ownership. Keep every
 * pin on error so the next listener owner can retry exact detach.
 */
static inline int asterisk_cgroup_detach_pins(const char *cgroup_path, const char *root) {
    int cgroup = -1;
    int result = 0;
    for (size_t i = 0U; i < ASTERISK_CGROUP_PROGRAM_COUNT; ++i) {
        const struct asterisk_cgroup_program *program = &asterisk_cgroup_programs[i];
        char path[ASTERISK_CGROUP_PATH_MAX];
        if (asterisk_cgroup_path(path, sizeof(path), root, program->pin) != 0) {
            result = -1;
            break;
        }
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.pathname = (uintptr_t)path;
        int fd = asterisk_cgroup_sys(BPF_OBJ_GET, &attr);
        if (fd < 0) {
            if (errno == ENOENT) continue;
            result = -1;
            break;
        }
        struct bpf_prog_info info;
        if (asterisk_cgroup_info(fd, &info) != 0 || info.id == 0U ||
            info.type != BPF_PROG_TYPE_CGROUP_SOCK_ADDR ||
            memcmp(info.name, program->name, strlen(program->name) + 1U) != 0) {
            close(fd);
            errno = ESTALE;
            result = -1;
            break;
        }
        if (cgroup < 0) cgroup = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (cgroup < 0) {
            close(fd);
            result = -1;
            break;
        }
        int attached = asterisk_cgroup_has_id(cgroup, program->type, info.id);
        if (attached > 0) {
            memset(&attr, 0, sizeof(attr));
            attr.target_fd = (uint32_t)cgroup;
            attr.attach_bpf_fd = (uint32_t)fd;
            attr.attach_type = program->type;
            if (asterisk_cgroup_sys(BPF_PROG_DETACH, &attr) != 0) {
                attached = -1;
            } else {
                attached = asterisk_cgroup_has_id(cgroup, program->type, info.id);
            }
        }
        close(fd);
        if (attached != 0) {
            result = -1;
            break;
        }
    }
    if (cgroup >= 0) close(cgroup);
    return result;
}

/* Detaches every pinned program, then removes the pins. */
static inline int asterisk_cgroup_reconcile(const char *cgroup_path, const char *root) {
    if (asterisk_cgroup_detach_pins(cgroup_path, root) != 0) return -1;
    for (size_t i = 0U; i < ASTERISK_CGROUP_PROGRAM_COUNT; ++i) {
        char path[ASTERISK_CGROUP_PATH_MAX];
        if (asterisk_cgroup_path(path, sizeof(path), root, asterisk_cgroup_programs[i].pin) != 0) return -1;
        if (unlink(path) != 0 && errno != ENOENT) return -1;
    }
    return 0;
}

#endif
