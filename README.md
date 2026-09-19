
# Changes to `ring' in version 1.0.2
- Distribute the application into Separate Discrete Function Files 
- Include IPv6 Support
- Include ARP functions - build a display and ARP Table
  Use ARP to enumerate hosts in a more detailed scan


# ring

`ring` is a lightweight IPv4 ICMP network diagnostic utility written in Rust.

The project began as an exercise in understanding how `ping` works at the packet and socket level and has grown into a small network diagnostic tool supporting ICMP reachability testing, latency measurement, route tracing, Linux extended ICMP error reporting, and structured JSON output.

Unlike a wrapper around the system `ping` command, `ring` constructs ICMP Echo Request packets and communicates directly with Linux ICMP sockets.

> **Current release:** v0.1.0
> **Platform:** Linux
> **Protocol:** IPv4 / ICMPv4
> **IPv6:** Not yet supported

---

## Features

### ICMP Reachability

Test whether a host responds to an ICMP Echo Request:

```bash
ring 192.168.1.1
```

Example:

```text
192.168.1.1 ALIVE seq=1 ttl=64 hops≈0 time=0.842 ms
```

Hostnames are resolved automatically:

```bash
ring google.com
```

Example:

```text
google.com (142.250.141.102) ALIVE seq=1 ttl=251 hops≈4 time=42.839 ms
```

---

## Multiple Probes

Send a specific number of requests with `-c` or `--count`:

```bash
ring -c 5 192.168.1.1
```

Statistics include:

* Packets transmitted
* Packets received
* Packet loss
* Elapsed time
* Minimum RTT
* Average RTT
* Maximum RTT
* Mean deviation
* Minimum, average, and maximum received TTL

---

## Continuous Mode

Use `-z` or `--continuous` to continue probing until interrupted:

```bash
ring -z 192.168.1.1
```

Press `Ctrl+C` to stop the test and display statistics.

`--continuous` and `--count` are mutually exclusive.

---

## Payload Size

Change the ICMP payload size with:

```bash
ring -s 128 192.168.1.1
```

The default payload is:

```text
56 bytes
```

The current maximum is:

```text
65507 bytes
```

---

## Timeout

Set the response timeout in milliseconds:

```bash
ring -t 500 192.168.1.1
```

The default timeout is:

```text
2000 ms
```

---

## Probe Interval

Set the delay between probes:

```bash
ring -i 250 -c 10 192.168.1.1
```

The default interval is:

```text
1000 ms
```

---

# Route Tracing

`ring` can trace the IPv4 route toward a destination by manipulating the outgoing IP TTL and observing ICMP Time Exceeded responses.

```bash
ring --route 1.1.1.1
```

Example output:

```text
Tracing route to 1.1.1.1, maximum 30 hops

 1  192.168.1.1                                   0.842 ms
 2  10.10.0.1                                     4.317 ms
 3  * 
 4  203.0.113.1                                  15.428 ms
 ...
 8  1.1.1.1                                      21.752 ms

Route = 8 hops
```

A `*` indicates that no usable response was received for that TTL.

### Maximum Hops

The default maximum route depth is 30 hops.

It can be changed with:

```bash
ring --route --max-hops 64 1.1.1.1
```

### Verbose Route Mode

Use `-v` or `--verbose` for additional route statistics:

```bash
ring --route -v 1.1.1.1
```

Verbose route mode defaults to three probes per hop and reports:

```text
Hop Address                         RespLoss       Min       Avg       Max      mdev      ΔAvg
```

`RespLoss` represents probes at that TTL for which no response was received.

`ΔAvg` is the difference between the average observed RTT of the current responding hop and the previous responding hop. It should not be interpreted as a direct measurement of latency between those two routers.

The probe count can be overridden:

```bash
ring --route -v -c 5 1.1.1.1
```

### Reverse DNS

Resolve responding router addresses to hostnames:

```bash
ring --route --resolve 1.1.1.1
```

Reverse DNS lookups can make route tracing slower because each responding address may require a DNS lookup.

---

# ICMP Error Reporting

On Linux, `ring` enables the extended socket error queue using `IP_RECVERR`.

This allows the program to distinguish several network conditions instead of reporting every unsuccessful request simply as a timeout.

Recognized conditions include:

* Network unreachable
* Host unreachable
* Protocol unreachable
* Port unreachable
* Fragmentation needed
* Source route failed
* Administratively prohibited
* TTL exceeded
* Parameter problem
* Network down
* Permission denied
* Other ICMP errors
* Local socket errors

Extended ICMP errors are correlated with the sequence number of the request that generated them.

A timeout still does **not** prove that a host is offline. Firewalls and operating systems commonly discard ICMP Echo Requests without returning an error.

---

# JSON Output

Normal ping results can be emitted as structured JSON for scripts and other applications:

```bash
ring -c 3 google.com --json
```

Example:

```json
{
  "schema_version": 1,
  "mode": "ping",
  "target": "google.com",
  "address": "142.250.141.102",
  "transmitted": 3,
  "received": 3,
  "probes": [
    {
      "sequence": 1,
      "status": "alive",
      "rtt_ms": 42.839,
      "ttl": 251
    },
    {
      "sequence": 2,
      "status": "alive",
      "rtt_ms": 41.571,
      "ttl": 251
    },
    {
      "sequence": 3,
      "status": "alive",
      "rtt_ms": 43.217,
      "ttl": 251
    }
  ]
}
```

This can be combined with tools such as `jq`:

```bash
ring google.com --json | jq -r '.probes[0].status'
```

or:

```bash
ring -c 3 google.com --json | jq -r '.probes[].rtt_ms'
```

The JSON format contains a `schema_version` field so the structured interface can evolve while remaining identifiable to scripts.

In v0.1.0, JSON output is intended for normal ping mode. Route, broadcast, and sweep JSON output are not yet implemented.

---

# TTL and Estimated Return Hops

For successful Echo Replies, `ring` displays the received IPv4 TTL:

```text
1.1.1.1 ALIVE seq=1 ttl=59 hops≈5 time=56.182 ms
```

`hops≈5` is an **estimate**, not a measured route length.

`ring` assumes a likely initial TTL of 64, 128, or 255 and calculates the approximate number of TTL decrements observed on the return path.

Actual route tracing with:

```bash
ring --route TARGET
```

measures the forward route separately.

Forward and return paths on IP networks are not necessarily identical.

---

# Broadcast Interface Discovery

The `-b` / `--broadcast` option currently identifies usable local IPv4 broadcast interfaces:

```bash
ring -b
```

A particular interface can be selected with:

```bash
ring -b eth0
```

The current v0.1.0 implementation enumerates the interface address and calculated broadcast address.

Actual broadcast ICMP discovery is planned for a future release.

---

# IPv4 Sweep Framework

`ring` contains the initial network-selection and safety framework for IPv4 host sweeping.

Examples of supported range definitions include:

```bash
ring -S
```

Derive ranges from usable local IPv4 interfaces.

```bash
ring -S eth0
```

Use a specific local interface.

An explicit inclusive range can be specified:

```bash
ring -S --low 192.168.1.20 --high 192.168.1.80
```

A network and subnet mask can also be supplied:

```bash
ring -S --network 192.168.1.0 --mask 255.255.255.0
```

CIDR notation is supported:

```bash
ring -S --network 192.168.1.0/24
```

### Sweep Safety

The sweep framework applies safeguards to prevent accidental probing of unexpectedly large or public address ranges.

Small RFC1918 private ranges are accepted automatically.

Larger RFC1918 ranges require confirmation:

```text
10.0.0.1 - 10.0.255.254
```

`-y` / `--yes` can automatically approve permitted RFC1918 private sweeps.

Non-RFC1918 ranges require the explicit:

```bash
--force
```

option.

`--force` is also required for extremely large ranges.

These safeguards do not override malformed subnet masks or otherwise invalid network definitions.

> **v0.1.0 note:** The sweep engine itself is not yet implemented. The current implementation validates and calculates sweep ranges but does not yet transmit concurrent ICMP probes to those addresses.

---

# Installation

## Build from Source

`ring` requires Rust and Cargo.

Clone the repository:

```bash
git clone <repository-url>
cd ring
```

Build a release binary:

```bash
cargo build --release
```

The resulting executable will be:

```text
target/release/ring
```

Install it for the current user:

```bash
mkdir -p ~/.local/bin
install -m 755 target/release/ring ~/.local/bin/ring
```

Make sure `~/.local/bin` is in your `PATH`.

Verify:

```bash
ring --version
ring --help
```

---

# Linux ICMP Ping Sockets

`ring` currently uses:

```text
AF_INET
SOCK_DGRAM
IPPROTO_ICMP
```

rather than opening a raw IPv4 socket for ordinary ICMP Echo Requests.

On Linux, this allows unprivileged ICMP operation when the user's group is permitted by:

```bash
sysctl net.ipv4.ping_group_range
```

Check the current configuration with:

```bash
sysctl net.ipv4.ping_group_range
```

Therefore, under a normally configured Linux system, `ring` should **not require root or `CAP_NET_RAW`** for its normal IPv4 ping functionality.

---

# Current Limitations

Version 0.1.0 is intentionally an early IPv4/Linux implementation.

Current limitations include:

* Linux only
* IPv4 only
* No ICMPv6 support
* No IPv6 route tracing
* No IPv6 Neighbor Discovery
* Broadcast mode currently enumerates interfaces rather than probing
* Sweep mode currently calculates and validates ranges rather than probing
* JSON output is currently limited to normal ping mode
* Route probing is currently sequential
* Reverse DNS is synchronous

These limitations provide areas for continued development rather than being hidden behind incomplete interfaces.

---

# Planned Development

Potential future development includes:

* Concurrent IPv4 host sweeping
* IPv4 broadcast discovery
* IPv6 / ICMPv6 support
* IPv6 Neighbor Discovery
* JSON route output
* JSON sweep output
* Improved route probe correlation and multipath reporting
* Fixed per-probe deadlines using event-driven socket polling
* Source address/interface selection
* IPv6 `-6` and IPv4 `-4` selection
* Additional machine-readable network diagnostics

The longer-term goal is to keep `ring` useful as a small command-line networking utility while also keeping the low-level networking implementation understandable.

---

# Why `ring`?

This project is also intended as a practical exploration of networking and systems programming in Rust.

Rather than hiding ICMP behind a high-level packet library, the implementation works directly with operating-system networking interfaces and manually handles several pieces of the protocol.

Development has included:

* ICMP Echo packet construction
* Internet checksum calculation
* Linux ICMP datagram sockets
* `sendto()` and `recvmsg()`
* Ancillary control messages
* Received TTL extraction
* Linux extended socket error queues
* `sock_extended_err`
* ICMP error classification
* Probe sequence correlation
* IPv4 interface enumeration with `getifaddrs()`
* IPv4 subnet and broadcast calculation
* CIDR and subnet-mask handling
* Route tracing through TTL manipulation
* RTT statistics
* Structured serialization with Serde

Because of this, some functionality that could be obtained from an existing high-level networking crate is deliberately implemented closer to the operating-system networking API.

---

# License

Add the license selected for the project here.

For example:

```text
MIT License
```

or:

```text
MIT OR Apache-2.0
```

See the `LICENSE` file for details.
