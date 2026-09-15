// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
// Shared fixed TC resource contract; keep byte-identical in bpf2socks/asteriskd.
#ifndef ASTERISK_UDP6_RECOVERY_NETLINK_H
#define ASTERISK_UDP6_RECOVERY_NETLINK_H
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdbool.h>

/* Fixed, shared helper-owned slots; never replace another filter. Recovery is
 * confined to bridge replies on loopback. It is independent of hotspot TC. */
#define RECOVERY_PRIORITY 31998U
#define RECOVERY_HANDLE 0xb205U
#define RECOVERY_PROTOCOL ETH_P_IPV6
#define INGRESS_PARENT TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)
#define EGRESS_PARENT TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)

static inline long udp6_recovery_bpf_sys(enum bpf_cmd command, union bpf_attr *attr, unsigned size) {
    return syscall(__NR_bpf, command, attr, size);
}

struct tc_request {
    struct nlmsghdr header;
    struct tcmsg message;
    unsigned char attributes[256];
};

static inline int route_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 2};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    return fd;
}

static inline void request_init(struct tc_request *request, unsigned type, unsigned flags,
                         unsigned ifindex, unsigned parent) {
    memset(request, 0, sizeof(*request));
    request->header.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    request->header.nlmsg_type = type;
    request->header.nlmsg_flags = NLM_F_REQUEST | flags;
    request->header.nlmsg_seq = 1U;
    request->message.tcm_family = AF_UNSPEC;
    request->message.tcm_ifindex = (int)ifindex;
    request->message.tcm_parent = parent;
}

static inline struct rtattr *attribute(struct tc_request *request, unsigned type,
                               const void *data, size_t length) {
    size_t offset = NLMSG_ALIGN(request->header.nlmsg_len);
    size_t end = offset + RTA_ALIGN(RTA_LENGTH(length));
    if (end > sizeof(*request)) return NULL;
    struct rtattr *attr = (void *)((unsigned char *)request + offset);
    attr->rta_type = type;
    attr->rta_len = RTA_LENGTH(length);
    if (length != 0U) memcpy(RTA_DATA(attr), data, length);
    request->header.nlmsg_len = end;
    return attr;
}

static inline int send_request(int fd, const struct tc_request *request) {
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    return sendto(fd, request, request->header.nlmsg_len, 0,
                  (const struct sockaddr *)&kernel, sizeof(kernel)) < 0 ? -1 : 0;
}

static inline int transaction(const struct tc_request *request) {
    int fd = route_socket();
    if (fd < 0) return -1;
    int result = send_request(fd, request);
    unsigned char buffer[4096];
    while (result == 0) {
        ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) { result = -1; break; }
        int remaining = (int)length;
        for (struct nlmsghdr *h = (void *)buffer; NLMSG_OK(h, (unsigned)remaining);
             h = NLMSG_NEXT(h, remaining)) {
            if (h->nlmsg_type != NLMSG_ERROR || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) continue;
            int error = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
            close(fd);
            if (error != 0) { errno = -error; return -1; }
            return 0;
        }
    }
    int saved = errno; close(fd); errno = saved; return result;
}

static inline bool owned_program(unsigned id, const char *name) {
    union bpf_attr attr = {0};
    attr.prog_id = id;
    int fd = (int)udp6_recovery_bpf_sys(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
    if (fd < 0) return false;
    struct bpf_prog_info info = {0};
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uint64_t)(uintptr_t)&info;
    int result = (int)udp6_recovery_bpf_sys(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    close(fd);
    return result == 0 && strncmp((const char *)info.name, name, sizeof(info.name)) == 0;
}

/* Return the exact slot's state (0 absent, 1 ours, 2 foreign); count all
 * filters separately before removing a clsact container created by us. */
static inline int inspect_filters(unsigned ifindex, unsigned parent, const char *name, unsigned *total) {
    struct tc_request request;
    request_init(&request, RTM_GETTFILTER, NLM_F_DUMP, ifindex, parent);
    int fd = route_socket();
    if (fd < 0) return -1;
    if (send_request(fd, &request) < 0) { int saved = errno; close(fd); errno = saved; return -1; }
    int found = 0;
    unsigned char buffer[16384];
    for (;;) {
        ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) { int saved = errno; close(fd); errno = saved; return -1; }
        int remaining = (int)length;
        for (struct nlmsghdr *h = (void *)buffer; NLMSG_OK(h, (unsigned)remaining);
             h = NLMSG_NEXT(h, remaining)) {
            if (h->nlmsg_type == NLMSG_DONE) { close(fd); return found; }
            if (h->nlmsg_type == NLMSG_ERROR) {
                int error = h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr))
                    ? ((struct nlmsgerr *)NLMSG_DATA(h))->error : -EPROTO;
                close(fd);
                if (error == -EINVAL || error == -ENOENT) return found;
                errno = error < 0 ? -error : EPROTO; return -1;
            }
            if (h->nlmsg_type != RTM_NEWTFILTER || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct tcmsg))) continue;
            struct tcmsg *message = NLMSG_DATA(h);
            ++*total;
            if (message->tcm_handle != RECOVERY_HANDLE ||
                (message->tcm_info >> 16U) != RECOVERY_PRIORITY ||
                (message->tcm_info & 0xffffU) != htons(RECOVERY_PROTOCOL)) continue;
            unsigned id = 0U;
            unsigned chain = 0U;
            bool bpf_kind = false;
            int left = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*message));
            for (struct rtattr *a = TCA_RTA(message); RTA_OK(a, left); a = RTA_NEXT(a, left)) {
                if (a->rta_type == TCA_CHAIN && RTA_PAYLOAD(a) == sizeof(chain)) memcpy(&chain, RTA_DATA(a), sizeof(chain));
                if (a->rta_type == TCA_KIND && RTA_PAYLOAD(a) == 4U && memcmp(RTA_DATA(a), "bpf", 4U) == 0) bpf_kind = true;
                if (a->rta_type != TCA_OPTIONS) continue;
                int options = RTA_PAYLOAD(a);
                for (struct rtattr *o = RTA_DATA(a); RTA_OK(o, options); o = RTA_NEXT(o, options)) {
                    if (o->rta_type == TCA_BPF_ID && RTA_PAYLOAD(o) == sizeof(id)) memcpy(&id, RTA_DATA(o), sizeof(id));
                }
            }
            if (chain != 0U) continue;
            found = 2;
            if (bpf_kind && id != 0U && owned_program(id, name)) found = 1;
        }
    }
}

static inline int filter_change(unsigned ifindex, unsigned parent, int program, bool remove) {
    struct tc_request request;
    request_init(&request, remove ? RTM_DELTFILTER : RTM_NEWTFILTER,
                 NLM_F_ACK | (remove ? 0U : NLM_F_CREATE | NLM_F_EXCL), ifindex, parent);
    request.message.tcm_handle = RECOVERY_HANDLE;
    request.message.tcm_info = (RECOVERY_PRIORITY << 16U) | htons(RECOVERY_PROTOCOL);
    if (!remove) {
        (void)attribute(&request, TCA_KIND, "bpf", 4U);
        struct rtattr *options = attribute(&request, TCA_OPTIONS, NULL, 0U);
        unsigned flags = TCA_BPF_FLAG_ACT_DIRECT;
        (void)attribute(&request, TCA_BPF_FD, &program, sizeof(program));
        (void)attribute(&request, TCA_BPF_FLAGS, &flags, sizeof(flags));
        options->rta_len = (unsigned char *)&request + request.header.nlmsg_len - (unsigned char *)options;
    }
    return transaction(&request);
}

static inline int udp6_recovery_reconcile(bool remove) {
    unsigned loopback = if_nametoindex("lo");
    if (loopback == 0U) return 0;
    const unsigned parents[2] = {INGRESS_PARENT, EGRESS_PARENT};
    const char *names[2] = {"b2s_u6_recover", "b2s_u6_record"};
    int result = 0;
    for (unsigned i = 0U; i < 2U; ++i) {
        unsigned total = 0U;
        int state = inspect_filters(loopback, parents[i], names[i], &total);
        if (state < 0) { result = -1; continue; }
        if (state != 1) continue;
        if (!remove) { errno = EBUSY; result = -1; continue; }
        if (filter_change(loopback, parents[i], -1, true) < 0) { result = -1; continue; }
        total = 0U;
        state = inspect_filters(loopback, parents[i], names[i], &total);
        if (state < 0 || state == 1) { errno = EBUSY; result = -1; }
    }
    return result;
}
#endif
