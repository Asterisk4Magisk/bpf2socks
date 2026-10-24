// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "core/probe.h"
#include "core/compat.h"
#include "core/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void set_probe_message(char *message, size_t message_size, const char *feature, int error) {
    if (message == NULL || message_size == 0U) return;
    snprintf(message, message_size, "%s is unavailable: errno=%d", feature, error);
}

static int probe_setsockopt(
    const char *feature,
    int family,
    int type,
    int protocol,
    int level,
    int optname,
    int value,
    char *message,
    size_t message_size) {
    int fd = socket(family, type | SOCK_CLOEXEC, protocol);
    if (fd < 0) {
        set_probe_message(message, message_size, feature, errno);
        return -1;
    }
    int rc = setsockopt(fd, level, optname, &value, sizeof(value));
    int saved = errno;
    close(fd);
    if (rc != 0) {
        errno = saved;
        set_probe_message(message, message_size, feature, errno);
        return -1;
    }
    return 0;
}

int bpf2socks_probe_tcp_options(char *message, size_t message_size) {
    if (message != NULL && message_size > 0U) message[0] = '\0';
    if (probe_setsockopt(
            "TCP_FASTOPEN_CONNECT",
            AF_INET,
            SOCK_STREAM,
            0,
            IPPROTO_TCP,
            TCP_FASTOPEN_CONNECT,
            1,
            message,
            message_size) < 0) {
        return -1;
    }
    if (probe_setsockopt("TCP_FASTOPEN", AF_INET, SOCK_STREAM, 0, IPPROTO_TCP, TCP_FASTOPEN, 5, message, message_size) < 0) {
        return -1;
    }
    if (probe_setsockopt("TCP_QUICKACK", AF_INET, SOCK_STREAM, 0, IPPROTO_TCP, TCP_QUICKACK, 1, message, message_size) < 0) {
        return -1;
    }
    if (probe_setsockopt("TCP_CORK", AF_INET, SOCK_STREAM, 0, IPPROTO_TCP, TCP_CORK, 1, message, message_size) < 0) {
        return -1;
    }
    if (message != NULL && message_size > 0U) snprintf(message, message_size, "ok");
    return 0;
}


static void set_socket_timeout_1s(int fd) {
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

int bpf2socks_probe_splice(char *message, size_t message_size) {
    int listener_fd = -1;
    int client_fd = -1;
    int accepted_fd = -1;
    int pipe_fds[2] = {-1, -1};
    int result = -1;

    if (message != NULL && message_size > 0U) message[0] = '\0';

    listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener_fd < 0) {
        set_probe_message(message, message_size, "splice listener socket", errno);
        goto done;
    }
    int one = 1;
    (void)setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listener_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener_fd, 1) != 0) {
        set_probe_message(message, message_size, "splice loopback listener", errno);
        goto done;
    }
    socklen_t addr_len = sizeof(addr);
    if (getsockname(listener_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        set_probe_message(message, message_size, "splice listener address", errno);
        goto done;
    }

    client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client_fd < 0) {
        set_probe_message(message, message_size, "splice client socket", errno);
        goto done;
    }
    set_socket_timeout_1s(client_fd);
    if (connect(client_fd, (struct sockaddr *)&addr, addr_len) != 0) {
        set_probe_message(message, message_size, "splice loopback connect", errno);
        goto done;
    }
    accepted_fd = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
    if (accepted_fd < 0) {
        set_probe_message(message, message_size, "splice accept4", errno);
        goto done;
    }
    set_socket_timeout_1s(accepted_fd);

    if (pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC) != 0) {
        set_probe_message(message, message_size, "splice pipe2", errno);
        goto done;
    }

    char payload = 'x';
    if (send(client_fd, &payload, 1U, MSG_NOSIGNAL) != 1) {
        set_probe_message(message, message_size, "splice probe send", errno);
        goto done;
    }
    ssize_t moved = splice(
        accepted_fd,
        NULL,
        pipe_fds[1],
        NULL,
        1U,
        SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (moved != 1) {
        set_probe_message(message, message_size, "splice socket-to-pipe", moved < 0 ? errno : EIO);
        goto done;
    }
    moved = splice(
        pipe_fds[0],
        NULL,
        accepted_fd,
        NULL,
        1U,
        SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (moved != 1) {
        set_probe_message(message, message_size, "splice pipe-to-socket", moved < 0 ? errno : EIO);
        goto done;
    }
    char reply = '\0';
    if (recv(client_fd, &reply, 1U, MSG_WAITALL) != 1 || reply != payload) {
        set_probe_message(message, message_size, "splice probe recv", errno != 0 ? errno : EIO);
        goto done;
    }

    if (message != NULL && message_size > 0U) {
        snprintf(message, message_size, "ok");
    }
    result = 0;

done:
    bpf2socks_close_fd(&pipe_fds[0]);
    bpf2socks_close_fd(&pipe_fds[1]);
    bpf2socks_close_fd(&accepted_fd);
    bpf2socks_close_fd(&client_fd);
    bpf2socks_close_fd(&listener_fd);
    return result;
}
