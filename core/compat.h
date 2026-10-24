// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_COMPAT_H
#define BPF2SOCKS_CORE_COMPAT_H

/*
 * Linux socket constants that older NDK sysroots do not define. The values
 * are the kernel ABI, so they are valid on every supported kernel.
 */

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR IP_ORIGDSTADDR
#endif

#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 36
#endif
#ifndef IPV6_ORIGDSTADDR
#define IPV6_ORIGDSTADDR 74
#endif
#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR IPV6_ORIGDSTADDR
#endif
#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif
#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

#ifndef TCP_CORK
#define TCP_CORK 3
#endif
#ifndef TCP_QUICKACK
#define TCP_QUICKACK 12
#endif
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif
#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

#endif
