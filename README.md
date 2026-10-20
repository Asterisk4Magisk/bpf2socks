# bpf2socks

`bpf2socks` is a root Android/Linux traffic bridge. It uses cgroup and socket eBPF programs to retain original destinations, then forwards TCP and UDP through a SOCKS5 upstream. It supports UID policy, private/direct CIDR policy, interface policy, DNS transaction tracking, connected UDP, full-cone UDP reply bindings, worker sharding, and runtime statistics.

The source root includes a standalone GNU Make build for Linux and Android. A parent Android project may still compile all top-level `.c` files together as a PIE executable, commonly packaged as `libbpf2socks.so`.

## Standalone build

GNU Make and a C compiler are required. Run all commands from the repository root.

### Linux

```sh
make
# Equivalent explicit target:
make linux
```

The output is `build/linux/bpf2socks`. Override standard Make variables such as `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, and `LDLIBS` when needed.

`tc_redirect.bpf.c` is compiled for the BPF target and embedded into the executable. Linux builds need a BPF-capable Clang (`BPF_CLANG`, default `clang`) and the host UAPI headers (`BPF_INCLUDE_FLAGS`); Android builds use the NDK Clang and sysroot.

### Android

Install the Android NDK, then expose it through `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, `ANDROID_SDK_ROOT`, or `ANDROID_HOME`.

```sh
# Build arm64-v8a, armeabi-v7a, x86, and x86_64:
make android

# Build one ABI:
make android ABI=arm64-v8a

# Override the default API level 24:
make android ABI=arm64-v8a ANDROID_API=26
```

Android outputs are written to `build/android/<abi>/libbpf2socks.so`. They are PIE executables despite the `.so` packaging suffix. Android-specific flag overrides are available through `ANDROID_CPPFLAGS`, `ANDROID_CFLAGS`, `ANDROID_LDFLAGS`, and `ANDROID_LDLIBS`.

Linux, macOS, and Windows NDK hosts are supported. On Windows, run GNU Make from an environment with a POSIX shell, such as MSYS2 or Git Bash, and use forward-slash paths when setting an NDK directory explicitly.

### Clean

```sh
make clean
```

This removes only the repository-local `build/` directory.

## Command line

```text
bpf2socks --probe [--config FILE]
bpf2socks --start --config FILE --pid FILE
bpf2socks --stop --config FILE --pid FILE
bpf2socks --stats --pid FILE
```

`--probe` prints a JSON capability result and can use a configuration to probe its requested IPv6/policy features. `--start` loads BPF state and starts the bridge; it holds `<pid>.lock` for its lifetime. `--stop` signals the PID only while that lock is held, so a stale PID file never signals an unrelated process, waits up to 10 seconds for the instance to finish its own cleanup, and then cleans resources described by the same configuration. `--pid /dev/null` disables the PID, lock, and statistics files for a caller that supervises the process itself. `--stats` prints JSON bridge counters (written only with `debugStats` and a real PID path). Missing required arguments return `2`; runtime failures return `1`; success returns `0`.

Per-packet and per-connection failures are logged on the 1st, 2nd, 4th, 8th... occurrence of each message, so a persistent fault cannot flood the log.

## Configuration example

```json
{
  "version": 1,
  "socksHost": "127.0.0.1",
  "socksPort": 1080,
  "bridgeListenAddress": "0.0.0.0",
  "bridgePort": 65532,
  "pinnedObjectDir": "/sys/fs/bpf/example/bpf2socks",
  "cgroupPath": "/sys/fs/cgroup",
  "enableIpv6": true,
  "enableDnsHijack": true,
  "debugStats": false,
  "tokenIpv4Prefix": "127.128.0.0/9",
  "tokenIpv6Prefix": "fd7a:7374:6572:6973::/64",
  "workerCount": 0,
  "tcpBufferSize": 0,
  "maxTcpSessions": 4096,
  "connectTimeoutMilliseconds": 10000,
  "tcpIdleTimeoutMilliseconds": 0,
  "udpSocketBufferSize": 524288,
  "udpBatchSize": 32,
  "maxUdpSessions": 4096,
  "maxUdpBindings": 16384,
  "udpIdleTimeoutSeconds": 60,
  "maxUdpPendingBytes": 67108864,
  "dnsTransactionTimeoutMilliseconds": 60000,
  "hotspotInterfacePrefixes": ["wlan+"],
  "ignoredInterfaces": ["lo", "wlan0", "wlan+"],
  "proxyPrivateCidrsV4": ["10.0.0.0/8"],
  "bypassPrivateCidrsV4": ["192.168.0.0/16"],
  "proxyPrivateCidrsV6": ["fd00::/8"],
  "bypassPrivateCidrsV6": ["fe80::/10"],
  "policy": {
    "mode": 2,
    "uids": [],
    "bypassUids": [],
    "bypassDirectCidrs": false,
    "directCidrPathV4": "/data/local/tmp/example/direct-v4.txt",
    "directCidrPathV6": "/data/local/tmp/example/direct-v6.txt"
  }
}
```

### Required top-level fields

| Field | Description |
| --- | --- |
| `socksHost` | SOCKS5 server address. |
| `socksPort` | SOCKS5 server port; must be non-zero. |
| `bridgeListenAddress` | Local bridge listen address. |
| `bridgePort` | Local bridge port; must be non-zero. |
| `pinnedObjectDir` | Caller-selected directory for persistent BPF objects. |

`version` is accepted in generated configurations but is currently informational; the C parser does not branch on it.

A present field must be well formed: numbers are unsigned decimals within their type (ports at most 65535, `policy.mode` at most 2), strings and list entries must fit their buffers, and lists must not exceed their documented limits. A violation rejects the configuration instead of truncating or wrapping the value.

### Optional runtime fields

| Field | Default / normalization |
| --- | --- |
| `cgroupPath` | `/sys/fs/cgroup`. |
| `enableIpv6` | `false`. |
| `enableDnsHijack` | `false`. |
| `debugStats` | `false`; also enabled by `BPF2SOCKS_DEBUG_STATS=1` or `true`. |
| `tokenIpv4Prefix` | `127.128.0.0/9`; fixed token pool that avoids the lower half of loopback space. |
| `tokenIpv6Prefix` | `fd7a:7374:6572:6973::/64`; must retain the supported `/64` token layout. |
| `workerCount` | `0` selects 4 workers on systems with at least 8 online CPUs, otherwise 2; capped at 8 and by session capacities. |
| `tcpBufferSize` | `0`, which leaves TCP socket buffers to kernel autotuning. A non-zero value fixes both buffers of every bridge TCP socket, clamped to 4096–4194304 bytes; fixed buffers disable autotuning and cap throughput on high-latency hotspot links. |
| `maxTcpSessions` | 4096; zero resets to the default, maximum 8192. |
| `connectTimeoutMilliseconds` | 10000; normalized to 1000–60000. Bounds connecting to the SOCKS5 server and completing its handshake, for TCP relays and for the UDP ASSOCIATE of a new UDP session. |
| `tcpIdleTimeoutMilliseconds` | 0, which keeps idle relayed connections open as the proxy cores do; non-zero values are normalized to 1000–3600000. Hotspot client connections use TCP keepalive (60 s idle, six probes 10 s apart) to drop clients that left. |
| `udpSocketBufferSize` | 524288 bytes; zero resets to the default. |
| `udpBatchSize` | 32; zero resets to the default; capped at 64 datagrams per system call. |
| `maxUdpSessions` | 4096; zero resets to the default. |
| `maxUdpBindings` | 16384; raised to at least `maxUdpSessions`. |
| `udpIdleTimeoutSeconds` | 60; zero resets to the default. A session of a local client whose UDP socket is gone is released after about 0.5 s idle instead (found with a `sock_diag` dump; disabled for the run if the dump fails). TC hotspot sessions keep the full timeout. |
| `maxUdpPendingBytes` | 67108864; normalized to 131072–134217728. |
| `dnsTransactionTimeoutMilliseconds` | 60000; normalized to 1000–600000. |

### Policy fields

| Field | Description |
| --- | --- |
| `policy.mode` | `0` blacklist, `1` whitelist, `2` global; default `2`. |
| `policy.uids` | Selected UID list, up to 8192 entries. |
| `policy.bypassUids` | Forced bypass UID list, up to 8192 entries. |
| `policy.bypassDirectCidrs` | Load direct CIDR files and bypass matches. |
| `policy.directCidrPathV4` | IPv4 CIDR file used when direct bypass is enabled. |
| `policy.directCidrPathV6` | IPv6 CIDR file used when direct bypass and IPv6 are enabled. |
| `hotspotInterfacePrefixes` | Hotspot interface selectors, up to 64 entries. |
| `ignoredInterfaces` | Exact interface names (for example, `wlan0`) or case-sensitive prefix selectors ending in `+` (for example, `wlan+`), up to 64 entries. Each selector is 1–15 total ASCII characters: letters, digits, `_`, `.`, and `-`, with `+` allowed only as the final character after a non-empty prefix. |
| `proxyPrivateCidrsV4` / `proxyPrivateCidrsV6` | Private CIDRs explicitly proxied, up to 512 per family. |
| `bypassPrivateCidrsV4` / `bypassPrivateCidrsV6` | Private CIDRs explicitly bypassed, up to 512 per family. |

The bridge automatically bypasses its own effective GID so its SOCKS connections are not recaptured. This value is derived at runtime and is not a JSON field.

## Platform requirements and safety

Run as root with a mounted BPF filesystem, a usable cgroup hierarchy, the required BPF program/map/link types, and sufficient file-descriptor limits. The program attempts to raise `RLIMIT_NOFILE` to 65535 and further reduces configured capacities when the available limit is lower.

Cgroup hooks prefer multi-program attachment. If an exclusive attachment blocks it, the six connect/sendmsg/recvmsg hooks may temporarily replace an existing program only when its translated instructions are exactly `r0 = 1; exit`. Unknown programs, unreadable instructions, and other attachment modes remain conflicts. This behavior applies with or without DNS enhancement.

Original program file descriptors remain open for restoration during probe cleanup, failed startup, and graceful shutdown. Restoration attempts to reinstate the original program ID and exclusive flags, and refuses to overwrite an observed external change. Exclusive attachment has no atomic compare-and-replace operation on the supported older kernels, so concurrent external attachment changes cannot be fully excluded. Restoration is best-effort: failures produce warnings and cleanup continues. They do not invalidate a successful capability probe or replace an earlier startup failure. Final cleanup retries pending restoration once and releases saved references even if it fails. Process termination without cleanup cannot restore the original attachment.

Each UDP session or DNS channel owns its UDP ASSOCIATE relay port among all workers. Some servers (Xray) bind every association's relay socket to port 0 with `SO_REUSEPORT`, which can return a port another live association still holds; datagrams then reach the wrong association. An association answered with a port that is in use is replaced (up to three retries for a session; a DNS channel is rebuilt). A relay port equal to the SOCKS5 server port is a shared relay and is not checked.

Hotspot datagrams that the IP layer fragmented follow the verdict of their first fragment, which carries the ports. A later fragment that arrives without its first fragment's verdict is dropped rather than forwarded past the proxy. Fragments of other protocols pass unchanged. DNS responses larger than a hotspot client's route MTU fall back from the raw reply socket to a UDP socket so that the kernel can fragment them.

A local datagram whose token the bridge no longer knows is answered with an ICMP port unreachable. This happens when the token was evicted from the shared LRU token map, or when the datagram was sent to an instance that has since restarted. A connected socket then fails with `ECONNREFUSED`, and its application can reconnect instead of waiting on a silent drop. While the client's session still holds the connected binding, the bridge restores and republishes the token instead. Tokens of local sessions whose socket is found closed are deleted. A SOCKS5 UDP reply addressed by domain (ATYP 3) is matched to the session's most recently used binding with the same port.

For TCP, `getpeername()` on a proxied socket returns the original destination: the CONNECT hook records it by socket cookie, since the bridge consumes the TCP token on accept. A reset or error on either side of a relayed connection resets the other side, and a connection whose SOCKS5 handshake fails or times out is reset, so applications read `ECONNRESET` rather than an orderly EOF. Proxy cores answer CONNECT before dialing, so a refused destination still appears as a connection that the core then closes.

Sockets that an Android app explicitly bound to a network (`Network.bindSocket`, `bindProcessToNetwork`) are bypassed when that network is not a default network, so captive portal logins and cellular-only services use the network they chose. The bridge derives the default networks from the policy routing rules and refreshes them when the rules change. Sockets bound to a default network, as QUIC connection migration binds them, stay proxied, and so does every socket while the default networks are unknown.

Known UDP limitations:

- Sockets bound to a non-loopback device (`SO_BINDTODEVICE`, TCP included) and UDP-Lite datagrams are bypassed.
- A per-datagram `IP_PKTINFO` interface cannot be honored, and such datagrams are not delivered.
- Replies to peers that contacted a local socket directly are proxied like any other datagram, so server-role UDP (inbound P2P, a listening WireGuard port) does not work.
- With DNS hijacking enabled, port-53 traffic to private and LAN resolvers is proxied too.

Known TCP limitations:

- `getsockname()` on a proxied socket returns a loopback address, so protocols that announce the local address (FTP active mode, SIP) carry the wrong one.
- Application TCP keepalive and `TCP_USER_TIMEOUT` only probe the local bridge, not the remote path.
- Urgent data (`MSG_OOB`) is not relayed. MPTCP and SCTP sockets are bypassed.

The configuration controls pinned objects, cgroup attachment, PID signaling, and traffic interception. Generate it from trusted application state and use an application-specific `pinnedObjectDir`.

## Parent-project integration

Mount the repository root directly at `bpf2socks/src/main/native`. The parent owns NDK discovery, ABI selection, compiler flags, packaging, and Gradle tasks.

## License

GPL-3.0. See [LICENSE](LICENSE).
