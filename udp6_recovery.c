// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#include "bpf2socks.h"
#include "udp6_recovery_netlink.h"

void bpf2socks_udp6_recovery_cleanup(void) {
    if (udp6_recovery_reconcile(true) < 0) {
        fprintf(stderr, "failed to detach UDP6 recovery filters: errno=%d\n", errno);
    }
}
void bpf2socks_udp6_recovery_stop(struct bpf2socks_bpf_runtime *runtime) {
    if (!runtime->udp6_recovery_attached && !runtime->udp6_recovery_qdisc_created) return;
    bpf2socks_udp6_recovery_cleanup();
    if (runtime->udp6_recovery_qdisc_created) {
        unsigned loopback = if_nametoindex("lo"), total = 0U;
        if (loopback != 0U && inspect_filters(loopback, INGRESS_PARENT, "", &total) >= 0 &&
            inspect_filters(loopback, EGRESS_PARENT, "", &total) >= 0 && total == 0U) {
            struct tc_request request;
            request_init(&request, RTM_DELQDISC, NLM_F_ACK, loopback, TC_H_CLSACT);
            request.message.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0U);
            (void)transaction(&request);
        }
    }
    runtime->udp6_recovery_attached = false;
    runtime->udp6_recovery_qdisc_created = false;
}

int bpf2socks_udp6_recovery_start(struct bpf2socks_bpf_runtime *runtime) {
    if (runtime->udp6_recover_prog_fd < 0) return 0;
    unsigned loopback = if_nametoindex("lo"), total = 0U;
    if (loopback == 0U) return -1;
    int ingress = inspect_filters(loopback, INGRESS_PARENT, "b2s_u6_recover", &total);
    int egress = inspect_filters(loopback, EGRESS_PARENT, "b2s_u6_record", &total);
    if (ingress < 0 || egress < 0) return -1;
    if (ingress == 2 || egress == 2) { errno = EEXIST; return -1; }
    bpf2socks_udp6_recovery_cleanup();
    struct tc_request request;
    request_init(&request, RTM_NEWQDISC, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, loopback, TC_H_CLSACT);
    request.message.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0U);
    (void)attribute(&request, TCA_KIND, "clsact", 7U);
    if (transaction(&request) == 0) runtime->udp6_recovery_qdisc_created = true;
    else if (errno != EEXIST) return -1;
    runtime->udp6_recovery_attached = true;
    if (filter_change(loopback, EGRESS_PARENT, runtime->udp6_record_prog_fd, false) < 0 ||
        filter_change(loopback, INGRESS_PARENT, runtime->udp6_recover_prog_fd, false) < 0) {
        int saved = errno; bpf2socks_udp6_recovery_stop(runtime); errno = saved; return -1;
    }
    return 0;
}
