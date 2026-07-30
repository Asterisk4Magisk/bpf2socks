// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf2socks.h"

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>

static int register_socket(int map_fd, uint32_t worker_id, int socket_fd) {
    if (socket_fd < 0) return 0;
    if (map_fd < 0 || bpf2socks_update_map(map_fd, &worker_id, &socket_fd) < 0) {
        errno = map_fd < 0 ? EBADF : errno;
        return -1;
    }
    return 0;
}

static int attach_group(int socket_fd, int program_fd) {
    if (socket_fd < 0) return 0;
    if (program_fd < 0) {
        errno = EBADF;
        return -1;
    }
    return setsockopt(
        socket_fd,
        SOL_SOCKET,
        SO_ATTACH_REUSEPORT_EBPF,
        &program_fd,
        sizeof(program_fd));
}

int bpf2socks_reuseport_register_worker_sockets(
    const struct bpf2socks_runtime_config *config,
    uint32_t worker_id,
    int tcp4_fd,
    int udp4_fd,
    int tcp6_fd,
    int udp6_fd) {
    if (config == NULL ||
        register_socket(config->reuseport_tcp4_map_fd, worker_id, tcp4_fd) < 0 ||
        register_socket(config->reuseport_udp4_map_fd, worker_id, udp4_fd) < 0 ||
        register_socket(config->reuseport_tcp6_map_fd, worker_id, tcp6_fd) < 0 ||
        register_socket(config->reuseport_udp6_map_fd, worker_id, udp6_fd) < 0) {
        return -1;
    }
    if (worker_id != 0U) return 0;
    if (attach_group(tcp4_fd, config->reuseport_prog_fd) < 0 ||
        attach_group(udp4_fd, config->reuseport_prog_fd) < 0 ||
        attach_group(tcp6_fd, config->reuseport_prog_fd) < 0 ||
        attach_group(udp6_fd, config->reuseport_prog_fd) < 0) {
        return -1;
    }
    return 0;
}
