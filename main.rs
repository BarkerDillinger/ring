use clap::Parser;
use console::style;
use serde::Serialize;
use std::io::{self, Write};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_HEADER_SIZE: usize = 8;

const DEFAULT_PAYLOAD_SIZE: usize = 56;
const MAX_PAYLOAD_SIZE: usize = 65_507;
const DEFAULT_TIMEOUT_MILLISECONDS: u64 = 2_000;
const DEFAULT_INTERVAL_MILLISECONDS: u64 = 1_000;

#[derive(Parser, Debug)]
#[command(
    name = "ring",
    version,
    about = "Simple ICMP reachability and latency tool"
)]
struct Cli {
    #[arg(short = 'c', long, value_name = "COUNT")]
    count: Option<u32>,

    #[arg(short = 'z', long, conflicts_with = "count")]
    continuous: bool,

    /// Probe local IPv4 broadcast addresses
    #[arg(short = 'b', long)]
    broadcast: bool,

    /// ICMP payload size in bytes
    #[arg(
        short = 's',
        long = "size",
        value_name = "BYTES",
        default_value_t = DEFAULT_PAYLOAD_SIZE
    )]
    size: usize,

    /// Reply timeout in milliseconds
    #[arg(
        short = 't',
        long,
        value_name = "MILLISECONDS",
        default_value_t = DEFAULT_TIMEOUT_MILLISECONDS
    )]
    timeout: u64,

    /// Delay between requests in milliseconds
    #[arg(
        short = 'i',
        long = "interval",
        value_name = "MILLISECONDS",
        default_value_t = DEFAULT_INTERVAL_MILLISECONDS
    )]
    interval: u64,

    /// Host/IP normally, or interface name when -b is used
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Trace the route to the destination
    #[arg(long)]
    route: bool,

    /// Perform reverse DNS lookups for route hops
    #[arg(long, requires = "route")]
    resolve: bool,

    /// Display detailed route information
    #[arg(short = 'v', long, requires = "route")]
    verbose: bool,

    /// Maximum number of hops when tracing a route
    #[arg(long = "max-hops", value_name = "HOPS", default_value_t = 30)]
    max_hops: u8,

    /// Sweep IPv4 addresses for responding hosts
    #[arg(
        short = 'S',
        long,
        conflicts_with_all = ["broadcast", "json"]
    )]
    sweep: bool,

    /// Automatically confirm permitted large RFC1918 private-network sweeps
    #[arg(short = 'y', long = "yes", requires = "sweep")]
    yes: bool,

    /// Force a sweep regardless of network size or public/private address space
    #[arg(long, requires = "sweep")]
    force: bool,

    /// First IPv4 address in a manually specified sweep range
    #[arg(
        long,
        value_name = "ADDRESS",
        requires = "sweep",
        requires = "high",
        conflicts_with = "network"
    )]
    low: Option<Ipv4Addr>,

    /// Last IPv4 address in a manually specified sweep range
    #[arg(
        long,
        value_name = "ADDRESS",
        requires = "sweep",
        requires = "low",
        conflicts_with = "network"
    )]
    high: Option<Ipv4Addr>,

    /// IPv4 network to sweep
    #[arg(
        long,
        value_name = "NETWORK",
        requires = "sweep",
        conflicts_with_all = ["low", "high"]
    )]
    network: Option<String>,

    /// Subnet mask used with --network
    #[arg(long, value_name = "NETMASK", requires = "network")]
    mask: Option<Ipv4Addr>,

    /// Output structured results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug)]
#[repr(align(16))]
struct ControlBuffer {
    bytes: [u8; 64],
}

struct PingStats {
    transmitted: u32,
    received: u32,
    errors: u32,
    rtts: Vec<Duration>,
    ttls: Vec<u8>,
    started: Instant,
}

struct QueuedIcmpError {
    sequence: u16,
    result: PingResult,
}

struct RouteHop {
    hop: u8,
    address: Option<Ipv4Addr>,
    hostname: Option<String>,
    rtts: Vec<Duration>,
    probes_sent: u32,
    reached_destination: bool,
    multiple_responders: bool,
}

#[derive(Debug)]
struct RttStats {
    min: f64,
    avg: f64,
    max: f64,
    mdev: f64,
}

#[derive(Debug)]
struct Ipv4Interface {
    name: String,
    address: Ipv4Addr,
    network: Ipv4Addr,
    broadcast: Ipv4Addr,
    prefix_length: u8,
}

#[derive(Debug)]
struct SweepRange {
    first: Ipv4Addr,
    last: Ipv4Addr,
    network: Option<Ipv4Addr>,
    prefix_length: Option<u8>,
    interface_name: Option<String>,
}

#[derive(Serialize)]
struct JsonPingProbe {
    sequence: u16,
    status: JsonStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    rtt_ms: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<Ipv4Addr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    icmp_type: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    icmp_code: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct JsonPingOutput {
    schema_version: u32,
    mode: &'static str,
    target: String,
    address: Ipv4Addr,
    transmitted: u32,
    received: u32,
    probes: Vec<JsonPingProbe>,
}

impl PingStats {
    fn new() -> Self {
        Self {
            transmitted: 0,
            received: 0,
            errors: 0,
            rtts: Vec::new(),
            ttls: Vec::new(),
            started: Instant::now(),
        }
    }

    fn record_reply(&mut self, rtt: Duration, ttl: Option<u8>) {
        self.received += 1;
        self.rtts.push(rtt);

        if let Some(ttl) = ttl {
            self.ttls.push(ttl);
        }
    }

    fn print(&self, target: &str) {
        let elapsed_ms = self.started.elapsed().as_millis();

        let lost = self.transmitted.saturating_sub(self.received);

        let loss = if self.transmitted == 0 {
            0.0
        } else {
            (lost as f64 / self.transmitted as f64) * 100.0
        };

        println!();

        println!(
            "{}",
            style(format!("--- {target} ring statistics ---"))
                .cyan()
                .bold()
        );

        if self.errors == 0 {
            println!(
                "{} packets transmitted, {} received, {:.1}% packet loss, time {}ms",
                self.transmitted, self.received, loss, elapsed_ms
            );
        } else {
            println!(
                "{} packets transmitted, {} received, {} errors, {:.1}% packet loss, time {}ms",
                self.transmitted, self.received, self.errors, loss, elapsed_ms
            );
        }

        if let Some(stats) = calculate_rtt_stats(&self.rtts) {
            println!(
                "rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms",
                stats.min, stats.avg, stats.max, stats.mdev
            );
        }

        if !self.ttls.is_empty() {
            let min = *self.ttls.iter().min().unwrap();

            let max = *self.ttls.iter().max().unwrap();

            let avg = self.ttls.iter().map(|ttl| *ttl as f64).sum::<f64>() / self.ttls.len() as f64;

            println!("ttl min/avg/max = {}/{:.1}/{}", min, avg, max);

            let representative_ttl = avg.round() as u8;

            let hops = estimate_hops(representative_ttl);

            println!(
                "{}",
                style(format!("estimated route = ≈{hops} hops"))
                    .magenta()
                    .bold()
            );
        }
    }
}

impl RouteHop {
    fn responses(&self) -> usize {
        self.rtts.len()
    }

    fn response_loss(&self) -> f64 {
        if self.probes_sent == 0 {
            return 0.0;
        }

        let lost = self.probes_sent as usize - self.responses();

        lost as f64 / self.probes_sent as f64 * 100.0
    }

    fn stats(&self) -> Option<RttStats> {
        calculate_rtt_stats(&self.rtts)
    }
}

enum PingResult {
    Alive {
        rtt: Duration,
        ttl: Option<u8>,
    },

    NoResponse,

    NetworkUnreachable {
        from: Option<Ipv4Addr>,
    },

    HostUnreachable {
        from: Option<Ipv4Addr>,
    },

    ProtocolUnreachable {
        from: Option<Ipv4Addr>,
    },

    PortUnreachable {
        from: Option<Ipv4Addr>,
    },

    FragmentationNeeded {
        from: Option<Ipv4Addr>,
        mtu: Option<u32>,
    },

    SourceRouteFailed {
        from: Option<Ipv4Addr>,
    },

    AdministrativelyProhibited {
        from: Option<Ipv4Addr>,
    },

    TimeExceeded {
        from: Option<Ipv4Addr>,
        rtt: Option<Duration>,
    },

    ParameterProblem {
        from: Option<Ipv4Addr>,
    },

    NetworkDown,

    PermissionDenied,

    IcmpError {
        from: Option<Ipv4Addr>,
        icmp_type: u8,
        icmp_code: u8,
    },

    LocalError(String),
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum JsonStatus {
    Alive,
    NoResponse,
    NetworkUnreachable,
    HostUnreachable,
    ProtocolUnreachable,
    PortUnreachable,
    FragmentationNeeded,
    SourceRouteFailed,
    AdministrativelyProhibited,
    TimeExceeded,
    ParameterProblem,
    NetworkDown,
    PermissionDenied,
    IcmpError,
    LocalError,
}

/// Develop Ping Packets for Transmission
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let (chunks, remainder) = data.as_chunks::<2>();

    for chunk in chunks {
        let word = u16::from_be_bytes(*chunk);

        sum += word as u32;
    }

    if let Some(&byte) = remainder.first() {
        sum += (byte as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

fn build_echo_request(sequence: u16, payload_size: usize) -> Vec<u8> {
    let mut packet = vec![0u8; ICMP_HEADER_SIZE + payload_size];

    packet[0] = ICMP_ECHO_REQUEST;

    packet[1] = 0;

    packet[2] = 0;

    packet[3] = 0;

    packet[4] = 0;

    packet[5] = 0;

    packet[6..8].copy_from_slice(&sequence.to_be_bytes());

    for (i, byte) in packet[ICMP_HEADER_SIZE..].iter_mut().enumerate() {
        *byte = (i & 0xff) as u8;
    }

    let csum = checksum(&packet);

    packet[2..4].copy_from_slice(&csum.to_be_bytes());

    packet
}

fn create_ping_socket(timeout: Duration) -> io::Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let timeout = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();

        unsafe { libc::close(fd) };

        return Err(error);
    }

    let enable_ttl: libc::c_int = 1;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            &enable_ttl as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();

        unsafe { libc::close(fd) };

        return Err(error);
    }

    let enable_errors: libc::c_int = 1;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            &enable_errors as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();

        unsafe {
            libc::close(fd);
        }

        return Err(error);
    }

    Ok(fd)
}

fn set_socket_ttl(fd: i32, ttl: u8) -> io::Result<()> {
    let ttl_value: libc::c_int = ttl as libc::c_int;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl_value as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn resolve_target(target: &str) -> io::Result<Ipv4Addr> {
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    let addresses = (target, 0).to_socket_addrs()?;

    for address in addresses {
        if let SocketAddr::V4(address_v4) = address {
            return Ok(*address_v4.ip());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!("No IPv4 address found for {target}"),
    ))
}

fn send_echo_request(fd: i32, target: Ipv4Addr, packet: &[u8]) -> io::Result<()> {
    let destination = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,

        sin_port: 0,

        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(target.octets()),
        },

        sin_zero: [0; 8],
    };

    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &destination as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    if sent as usize != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "Incomplete ICMP packet transmission",
        ));
    }

    Ok(())
}

fn wait_for_reply(fd: i32, target: Ipv4Addr, sequence: u16, start: Instant) -> PingResult {
    let mut buffer = [0u8; 65535];

    loop {
        let mut source: libc::sockaddr_in = unsafe { mem::zeroed() };

        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };

        let mut control = ControlBuffer { bytes: [0u8; 64] };

        let mut message: libc::msghdr = unsafe { mem::zeroed() };

        message.msg_name = &mut source as *mut libc::sockaddr_in as *mut libc::c_void;

        message.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;

        message.msg_control = control.bytes.as_mut_ptr() as *mut libc::c_void;

        message.msg_controllen = control.bytes.len();

        let received = unsafe { libc::recvmsg(fd, &mut message, 0) };

        if received < 0 {
            let error = io::Error::last_os_error();

            // Before treating this as a timeout/local error,
            // check Linux's extended socket error queue.
            if let Some(queued_error) = read_error_queue(fd) {
                if queued_error.sequence != sequence {
                    continue;
                }

                let mut network_error = queued_error.result;

                if let PingResult::TimeExceeded { rtt, .. } = &mut network_error {
                    *rtt = Some(start.elapsed());
                }

                return network_error;
            }

            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PingResult::NoResponse,

                _ => classify_network_error(error),
            };
        }

        let packet = &buffer[..received as usize];

        if packet.len() < ICMP_HEADER_SIZE {
            continue;
        }

        let source_ip = Ipv4Addr::from(source.sin_addr.s_addr.to_ne_bytes());

        if source_ip != target {
            continue;
        }

        let icmp_type = packet[0];
        let icmp_code = packet[1];

        if icmp_type != ICMP_ECHO_REPLY || icmp_code != 0 {
            continue;
        }

        let reply_sequence = u16::from_be_bytes([packet[6], packet[7]]);

        if reply_sequence != sequence {
            continue;
        }

        let ttl = extract_ttl(&message);

        return PingResult::Alive {
            rtt: start.elapsed(),
            ttl,
        };
    }
}

fn duration_ms(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 1_000_000.0).round() / 1_000.0
}

/// Additional Network Identification Functions
fn extract_ttl(message: &libc::msghdr) -> Option<u8> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(message as *const libc::msghdr);

        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_TTL {
                let ttl_ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;

                let ttl = std::ptr::read_unaligned(ttl_ptr);

                return u8::try_from(ttl).ok();
            }

            cmsg = libc::CMSG_NXTHDR(message as *const libc::msghdr, cmsg);
        }
    }

    None
}

fn display_target(original: &str, resolved: Ipv4Addr) -> String {
    if original.parse::<Ipv4Addr>().is_ok() {
        resolved.to_string()
    } else {
        format!("{original} ({resolved})")
    }
}

fn get_ipv4_interfaces(requested_interface: Option<&str>) -> io::Result<Vec<Ipv4Interface>> {
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut interfaces = Vec::new();

    let mut current = ifaddrs;

    while !current.is_null() {
        let interface = unsafe { &*current };

        if !interface.ifa_addr.is_null()
            && unsafe { (*interface.ifa_addr).sa_family as i32 == libc::AF_INET }
        {
            let flags = interface.ifa_flags as i32;

            let is_up = flags & libc::IFF_UP != 0;

            let supports_broadcast = flags & libc::IFF_BROADCAST != 0;

            let is_loopback = flags & libc::IFF_LOOPBACK != 0;

            if is_up && supports_broadcast && !is_loopback {
                let name = unsafe { std::ffi::CStr::from_ptr(interface.ifa_name) }
                    .to_string_lossy()
                    .into_owned();

                if requested_interface.is_none_or(|requested| requested == name) {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in) };
                    let netmask = unsafe { &*(interface.ifa_netmask as *const libc::sockaddr_in) };
                    let ip = u32::from_be_bytes(address.sin_addr.s_addr.to_ne_bytes());
                    let mask = u32::from_be_bytes(netmask.sin_addr.s_addr.to_ne_bytes());

                    let broadcast = ip | !mask;

                    let network = ip & mask;
                    let prefix_length = mask.count_ones() as u8;

                    interfaces.push(Ipv4Interface {
                        name,
                        address: Ipv4Addr::from(ip),
                        network: Ipv4Addr::from(network),
                        broadcast: Ipv4Addr::from(broadcast),
                        prefix_length,
                    });
                }
            }
        }

        current = unsafe { (*current).ifa_next };
    }

    unsafe {
        libc::freeifaddrs(ifaddrs);
    }

    Ok(interfaces)
}

fn prefix_from_netmask(mask: Ipv4Addr) -> Option<u8> {
    let mask = u32::from(mask);

    let inverted = !mask;

    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }

    Some(mask.count_ones() as u8)
}

fn run_broadcast_mode(cli: &Cli) -> io::Result<()> {
    let requested_interface = cli.target.as_deref();
    let interfaces = get_ipv4_interfaces(requested_interface)?;

    if interfaces.is_empty() {
        match requested_interface {
            Some(name) => {
                eprintln!("ring: no usable IPv4 broadcast interface named {}", name);
            }

            None => {
                eprintln!("ring: no usable IPv4 broadcast interfaces found");
            }
        }

        std::process::exit(2);
    }

    println!("{}", style("Broadcast interfaces:").magenta().bold());

    for interface in &interfaces {
        println!(
            "{} {} {}",
            style(&interface.name).cyan().bold(),
            style(format!("address={}", interface.address)).green(),
            style(format!("broadcast={}", interface.broadcast))
                .yellow()
                .bold()
        );
    }

    Ok(())
}

fn estimate_hops(ttl: u8) -> u8 {
    let assumed_initial_ttl = match ttl {
        0..=64 => 64,
        65..=128 => 128,
        _ => 255,
    };

    assumed_initial_ttl - ttl
}

fn calculate_rtt_stats(rtts: &[Duration]) -> Option<RttStats> {
    if rtts.is_empty() {
        return None;
    }

    let rtts_ms: Vec<f64> = rtts.iter().map(|rtt| rtt.as_secs_f64() * 1000.0).collect();

    let min = rtts_ms.iter().copied().fold(f64::INFINITY, f64::min);

    let max = rtts_ms.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    let avg = rtts_ms.iter().sum::<f64>() / rtts_ms.len() as f64;

    let variance = rtts_ms
        .iter()
        .map(|rtt| {
            let difference = *rtt - avg;
            difference * difference
        })
        .sum::<f64>()
        / rtts_ms.len() as f64;

    Some(RttStats {
        min,
        avg,
        max,
        mdev: variance.sqrt(),
    })
}

fn reverse_dns(address: Ipv4Addr) -> Option<String> {
    let socket_address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    };

    let mut hostname = [0i8; libc::NI_MAXHOST as usize];

    let result = unsafe {
        libc::getnameinfo(
            &socket_address as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            hostname.as_mut_ptr(),
            hostname.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };

    if result != 0 {
        return None;
    }

    let hostname = unsafe { std::ffi::CStr::from_ptr(hostname.as_ptr()) };

    Some(hostname.to_string_lossy().into_owned())
}

fn run_route_mode(fd: i32, target: Ipv4Addr, target_display: &str, cli: &Cli) -> io::Result<()> {
    let probes_per_hop = route_probe_count(cli);

    println!(
        "{}",
        style(format!(
            "Tracing route to {target_display}, maximum {} hops",
            cli.max_hops
        ))
        .cyan()
        .bold()
    );

    if cli.verbose {
        println!(
            "{}",
            style(format!("{probes_per_hop} probes per hop")).dim()
        );
    }

    println!();

    if cli.verbose {
        println!(
            "{:<4} {:<32} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
            "Hop", "Address", "RespLoss", "Min", "Avg", "Max", "mdev", "ΔAvg"
        );
    }

    let mut sequence: u16 = 1;
    let mut previous_average: Option<f64> = None;

    let mut total_probes: u32 = 0;
    let mut total_responses: u32 = 0;

    for hop_number in 1..=cli.max_hops {
        set_socket_ttl(fd, hop_number)?;

        let mut route_hop = RouteHop {
            hop: hop_number,
            address: None,
            hostname: None,
            rtts: Vec::new(),
            probes_sent: 0,
            reached_destination: false,
            multiple_responders: false,
        };

        for _ in 0..probes_per_hop {
            let packet = build_echo_request(sequence, cli.size);

            let start = Instant::now();

            route_hop.probes_sent += 1;
            total_probes += 1;

            let result = match send_echo_request(fd, target, &packet) {
                Ok(()) => wait_for_reply(fd, target, sequence, start),

                Err(error) => classify_network_error(error),
            };

            match result {
                PingResult::TimeExceeded { from, rtt } => {
                    if let Some(address) = from {
                        match route_hop.address {
                            Some(existing) if existing != address => {
                                route_hop.multiple_responders = true;
                            }

                            None => {
                                route_hop.address = Some(address);
                            }

                            _ => {}
                        }
                    }

                    if let Some(rtt) = rtt {
                        route_hop.rtts.push(rtt);
                        total_responses += 1;
                    }
                }

                PingResult::Alive { rtt, .. } => {
                    if let Some(existing) = route_hop.address {
                        if existing != target {
                            route_hop.multiple_responders = true;
                        }
                    } else {
                        route_hop.address = Some(target);
                    }

                    route_hop.rtts.push(rtt);
                    route_hop.reached_destination = true;

                    total_responses += 1;
                }

                PingResult::NoResponse => {}

                _ => {}
            }

            sequence = sequence.wrapping_add(1);
        }

        if cli.resolve {
            route_hop.hostname = route_hop.address.and_then(reverse_dns);
        }

        if cli.verbose {
            print_route_statistics(&route_hop, &mut previous_average);
        } else {
            print_route_compact(&route_hop);
        }

        if route_hop.reached_destination {
            println!();

            println!(
                "{}",
                style(format!("Route = {} hops", hop_number)).green().bold()
            );

            if cli.verbose {
                println!(
                    "{} probes transmitted, {} responses",
                    total_probes, total_responses
                );
            }

            return Ok(());
        }
    }

    println!();

    println!(
        "{}",
        style(format!(
            "Destination not reached within {} hops",
            cli.max_hops
        ))
        .yellow()
        .bold()
    );

    if cli.verbose {
        println!(
            "{} probes transmitted, {} responses",
            total_probes, total_responses
        );
    }

    Ok(())
}

fn route_probe_count(cli: &Cli) -> u32 {
    match cli.count {
        Some(count) => count,
        None if cli.verbose => 3,
        None => 1,
    }
}

fn range_from_interface(interface: &Ipv4Interface) -> io::Result<SweepRange> {
    if interface.prefix_length >= 31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{}/{} is not supported for sweep mode",
                interface.network, interface.prefix_length
            ),
        ));
    }

    let network = u32::from(interface.network);
    let broadcast = u32::from(interface.broadcast);

    Ok(SweepRange {
        first: Ipv4Addr::from(network + 1),
        last: Ipv4Addr::from(broadcast - 1),
        network: Some(interface.network),
        prefix_length: Some(interface.prefix_length),
        interface_name: Some(interface.name.clone()),
    })
}

fn range_from_low_high(low: Ipv4Addr, high: Ipv4Addr) -> io::Result<SweepRange> {
    if u32::from(low) > u32::from(high) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LOW address must not be greater than HIGH address",
        ));
    }

    Ok(SweepRange {
        first: low,
        last: high,
        network: None,
        prefix_length: None,
        interface_name: None,
    })
}

fn range_from_network_mask(address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<SweepRange> {
    let prefix_length = prefix_from_netmask(mask).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{mask} is not a valid contiguous IPv4 subnet mask"),
        )
    })?;

    if prefix_length >= 31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "/31 and /32 networks are not supported for sweep mode",
        ));
    }

    let address_value = u32::from(address);
    let mask_value = u32::from(mask);

    let network = address_value & mask_value;
    let broadcast = network | !mask_value;

    Ok(SweepRange {
        first: Ipv4Addr::from(network + 1),
        last: Ipv4Addr::from(broadcast - 1),
        network: Some(Ipv4Addr::from(network)),
        prefix_length: Some(prefix_length),
        interface_name: None,
    })
}

fn range_from_cidr(cidr: &str) -> io::Result<SweepRange> {
    let (address_text, prefix_text) = cidr.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "CIDR must be written as ADDRESS/PREFIX",
        )
    })?;

    let address: Ipv4Addr = address_text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid IPv4 address: {address_text}"),
        )
    })?;

    let prefix: u8 = prefix_text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid prefix length: {prefix_text}"),
        )
    })?;

    if prefix > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 prefix length must be between 0 and 32",
        ));
    }

    if prefix >= 31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "/31 and /32 networks are not supported for sweep mode",
        ));
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    range_from_network_mask(address, Ipv4Addr::from(mask))
}

fn range_is_rfc1918(range: &SweepRange) -> bool {
    let first = u32::from(range.first);
    let last = u32::from(range.last);

    let private_ranges = [
        (
            u32::from(Ipv4Addr::new(10, 0, 0, 0)),
            u32::from(Ipv4Addr::new(10, 255, 255, 255)),
        ),
        (
            u32::from(Ipv4Addr::new(172, 16, 0, 0)),
            u32::from(Ipv4Addr::new(172, 31, 255, 255)),
        ),
        (
            u32::from(Ipv4Addr::new(192, 168, 0, 0)),
            u32::from(Ipv4Addr::new(192, 168, 255, 255)),
        ),
    ];

    private_ranges
        .iter()
        .any(|(start, end)| first >= *start && last <= *end)
}

fn sweep_range_size(range: &SweepRange) -> u64 {
    let first = u32::from(range.first) as u64;
    let last = u32::from(range.last) as u64;

    last - first + 1
}

fn confirm_sweep(range: &SweepRange, count: u64) -> io::Result<bool> {
    eprintln!(
        "WARNING: sweep range {} - {} contains {} IPv4 addresses.",
        range.first, range.last, count
    );

    eprint!("Continue? [y/N]: ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn validate_sweep_range(range: &SweepRange, yes: bool, force: bool) -> io::Result<bool> {
    let count = sweep_range_size(range);
    let private = range_is_rfc1918(range);

    if force {
        return Ok(true);
    }

    if !private {
        eprintln!(
            "ring: {} - {} is not entirely within RFC1918 private address space",
            range.first, range.last
        );

        eprintln!("Use --force to authorize sweeping non-private address space.");

        return Ok(false);
    }

    if count <= 254 {
        return Ok(true);
    }

    // -y can automatically approve larger RFC1918 ranges,
    // but not the extremely large ranges protected by --force.
    if count <= 65_534 {
        if yes {
            return Ok(true);
        }

        return confirm_sweep(range, count);
    }

    eprintln!(
        "ring: refusing sweep of {} IPv4 addresses without --force",
        count
    );

    eprintln!("Use --force to override the large-network safety limit.");

    Ok(false)
}

fn build_sweep_ranges(cli: &Cli) -> io::Result<Vec<SweepRange>> {
    let manual_scope =
        cli.low.is_some() || cli.high.is_some() || cli.network.is_some() || cli.mask.is_some();

    if manual_scope && cli.target.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an interface name cannot be combined with a manually specified sweep range",
        ));
    }

    if let (Some(low), Some(high)) = (cli.low, cli.high) {
        return Ok(vec![range_from_low_high(low, high)?]);
    }

    if let Some(network_text) = &cli.network {
        if network_text.contains('/') {
            if cli.mask.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--mask must not be used when --network is in CIDR notation",
                ));
            }

            return Ok(vec![range_from_cidr(network_text)?]);
        }

        let address: Ipv4Addr = network_text.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid IPv4 network address: {network_text}"),
            )
        })?;

        let mask = cli.mask.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--mask is required when --network is not in CIDR notation",
            )
        })?;

        return Ok(vec![range_from_network_mask(address, mask)?]);
    }

    let requested_interface = cli.target.as_deref();

    let interfaces = get_ipv4_interfaces(requested_interface)?;

    if interfaces.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            match requested_interface {
                Some(name) => format!("No usable IPv4 interface named {name}"),
                None => "No usable IPv4 interfaces found".to_string(),
            },
        ));
    }

    interfaces.iter().map(range_from_interface).collect()
}

fn run_sweep_mode(cli: &Cli) -> io::Result<()> {
    let ranges = build_sweep_ranges(cli)?;

    for range in &ranges {
        if !validate_sweep_range(range, cli.yes, cli.force)? {
            continue;
        }

        let count = sweep_range_size(range);

        match (&range.interface_name, range.prefix_length) {
            (Some(interface), Some(prefix)) => {
                eprintln!(
                    "Sweep: {} {}/{} -> {} - {} ({} addresses)",
                    interface,
                    range.network.unwrap(),
                    prefix,
                    range.first,
                    range.last,
                    count
                );
            }

            _ => {
                eprintln!(
                    "Sweep: {} - {} ({} addresses)",
                    range.first, range.last, count
                );
            }
        }
    }

    Ok(())
}

fn ping_result_to_json(sequence: u16, result: &PingResult) -> JsonPingProbe {
    match result {
        PingResult::Alive { rtt, ttl } => JsonPingProbe {
            sequence,
            status: JsonStatus::Alive,
            rtt_ms: Some(duration_ms(*rtt)),
            ttl: *ttl,
            from: None,
            mtu: None,
            icmp_type: None,
            icmp_code: None,
            error: None,
        },

        PingResult::NoResponse => JsonPingProbe {
            sequence,
            status: JsonStatus::NoResponse,
            rtt_ms: None,
            ttl: None,
            from: None,
            mtu: None,
            icmp_type: None,
            icmp_code: None,
            error: None,
        },

        PingResult::NetworkUnreachable { from } => {
            json_error_probe(sequence, JsonStatus::NetworkUnreachable, *from)
        }

        PingResult::HostUnreachable { from } => {
            json_error_probe(sequence, JsonStatus::HostUnreachable, *from)
        }

        PingResult::ProtocolUnreachable { from } => {
            json_error_probe(sequence, JsonStatus::ProtocolUnreachable, *from)
        }

        PingResult::PortUnreachable { from } => {
            json_error_probe(sequence, JsonStatus::PortUnreachable, *from)
        }

        PingResult::SourceRouteFailed { from } => {
            json_error_probe(sequence, JsonStatus::SourceRouteFailed, *from)
        }

        PingResult::AdministrativelyProhibited { from } => {
            json_error_probe(sequence, JsonStatus::AdministrativelyProhibited, *from)
        }

        PingResult::ParameterProblem { from } => {
            json_error_probe(sequence, JsonStatus::ParameterProblem, *from)
        }

        PingResult::TimeExceeded { from, rtt } => JsonPingProbe {
            sequence,
            status: JsonStatus::TimeExceeded,
            rtt_ms: rtt.map(duration_ms),
            ttl: None,
            from: *from,
            mtu: None,
            icmp_type: None,
            icmp_code: None,
            error: None,
        },

        PingResult::FragmentationNeeded { from, mtu } => JsonPingProbe {
            sequence,
            status: JsonStatus::FragmentationNeeded,
            rtt_ms: None,
            ttl: None,
            from: *from,
            mtu: *mtu,
            icmp_type: None,
            icmp_code: None,
            error: None,
        },

        PingResult::NetworkDown => json_error_probe(sequence, JsonStatus::NetworkDown, None),

        PingResult::PermissionDenied => {
            json_error_probe(sequence, JsonStatus::PermissionDenied, None)
        }

        PingResult::IcmpError {
            from,
            icmp_type,
            icmp_code,
        } => JsonPingProbe {
            sequence,
            status: JsonStatus::IcmpError,
            rtt_ms: None,
            ttl: None,
            from: *from,
            mtu: None,
            icmp_type: Some(*icmp_type),
            icmp_code: Some(*icmp_code),
            error: None,
        },

        PingResult::LocalError(message) => JsonPingProbe {
            sequence,
            status: JsonStatus::LocalError,
            rtt_ms: None,
            ttl: None,
            from: None,
            mtu: None,
            icmp_type: None,
            icmp_code: None,
            error: Some(message.clone()),
        },
    }
}

fn json_error_probe(sequence: u16, status: JsonStatus, from: Option<Ipv4Addr>) -> JsonPingProbe {
    JsonPingProbe {
        sequence,
        status,
        rtt_ms: None,
        ttl: None,
        from,
        mtu: None,
        icmp_type: None,
        icmp_code: None,
        error: None,
    }
}

/// Return Results
fn print_result(target: &str, sequence: u16, result: &PingResult, timeout: Duration) {
    let target_text = style(target).cyan().bold();
    let sequence_text = style(format!("seq={sequence}")).blue().bold();

    match result {
        PingResult::Alive { rtt, ttl } => {
            let milliseconds = rtt.as_secs_f64() * 1000.0;

            if let Some(ttl) = ttl {
                let hops = estimate_hops(*ttl);

                println!(
                    "{} {} {} {} {} {}",
                    target_text,
                    style("ALIVE").green().bold(),
                    sequence_text,
                    style(format!("ttl={ttl}")).cyan().bold(),
                    style(format!("hops≈{hops}")).magenta().bold(),
                    style(format!("time={milliseconds:.3} ms")).green().bold()
                );
            } else {
                println!(
                    "{} {} {} {}",
                    target_text,
                    style("ALIVE").green().bold(),
                    sequence_text,
                    style(format!("time={milliseconds:.3} ms")).green().bold()
                );
            }
        }

        PingResult::NoResponse => {
            println!(
                "{} {} {} {}",
                target_text,
                style("NO RESPONSE").yellow().bold(),
                sequence_text,
                style(format!("timeout={:.3} s", timeout.as_secs_f64()))
                    .yellow()
                    .bold()
            );
        }

        PingResult::NetworkUnreachable { from } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("NETWORK UNREACHABLE").red().bold(),
                sequence_text,
                style(format_error_source(from)).red()
            );
        }

        PingResult::HostUnreachable { from } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("HOST UNREACHABLE").red().bold(),
                sequence_text,
                style(format_error_source(from)).red()
            );
        }

        PingResult::ProtocolUnreachable { from } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("PROTOCOL UNREACHABLE").red().bold(),
                sequence_text,
                style(format_error_source(from)).red()
            );
        }

        PingResult::PortUnreachable { from } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("PORT UNREACHABLE").red().bold(),
                sequence_text,
                style(format_error_source(from)).red()
            );
        }

        PingResult::FragmentationNeeded { from, mtu } => {
            let mtu_text = match mtu {
                Some(mtu) => format!("mtu={mtu}"),
                None => "mtu=unknown".to_string(),
            };

            println!(
                "{} {} {} {} {}",
                target_text,
                style("FRAGMENTATION NEEDED").yellow().bold(),
                sequence_text,
                style(format_error_source(from)).yellow(),
                style(mtu_text).yellow().bold()
            );
        }

        PingResult::SourceRouteFailed { from } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("SOURCE ROUTE FAILED").red().bold(),
                sequence_text,
                style(format_error_source(from)).red()
            );
        }

        PingResult::AdministrativelyProhibited { from } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("ADMINISTRATIVELY PROHIBITED").magenta().bold(),
                sequence_text,
                style(format_error_source(from)).magenta().bold()
            );
        }

        PingResult::TimeExceeded { from, .. } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("TTL EXCEEDED").yellow().bold(),
                sequence_text,
                style(format_error_source(from)).yellow().bold()
            );
        }

        PingResult::ParameterProblem { from } => {
            println!(
                "{} {} {} {}",
                target_text,
                style("PARAMETER PROBLEM").red().bold(),
                sequence_text,
                style(format_error_source(from)).red()
            );
        }

        PingResult::NetworkDown => {
            println!(
                "{} {} {}",
                target_text,
                style("NETWORK DOWN").red().bold(),
                sequence_text
            );
        }

        PingResult::PermissionDenied => {
            println!(
                "{} {} {}",
                target_text,
                style("PERMISSION DENIED").magenta().bold(),
                sequence_text
            );
        }

        PingResult::IcmpError {
            from,
            icmp_type,
            icmp_code,
        } => {
            println!(
                "{} {} {} {} {}",
                target_text,
                style("ICMP ERROR").red().bold(),
                sequence_text,
                style(format!("type={icmp_type} code={icmp_code}"))
                    .red()
                    .bold(),
                style(format_error_source(from)).red()
            );
        }

        PingResult::LocalError(message) => {
            println!(
                "{} {} {} {}",
                target_text,
                style("LOCAL ERROR").red().bold(),
                sequence_text,
                style(format!("({message})")).red()
            );
        }
    }
}

fn print_route_statistics(hop: &RouteHop, previous_average: &mut Option<f64>) {
    let address_text = match hop.address {
        Some(address) => match &hop.hostname {
            Some(hostname) => {
                format!("{hostname} ({address})")
            }

            None => address.to_string(),
        },

        None => "*".to_string(),
    };

    let loss = hop.response_loss();

    match hop.stats() {
        Some(stats) => {
            let delta = match *previous_average {
                Some(previous) => {
                    format!("{:+.1}", stats.avg - previous)
                }

                None => "-".to_string(),
            };

            let responder_marker = if hop.multiple_responders { " +" } else { "" };

            println!(
                "{:<4} {:<32} {:>8.1}% {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9}",
                hop.hop,
                format!("{address_text}{responder_marker}"),
                loss,
                stats.min,
                stats.avg,
                stats.max,
                stats.mdev,
                delta
            );

            *previous_average = Some(stats.avg);
        }

        None => {
            println!(
                "{:<4} {:<32} {:>8.1}% {:>9} {:>9} {:>9} {:>9} {:>9}",
                hop.hop, address_text, loss, "-", "-", "-", "-", "-"
            );
        }
    }
}

fn print_route_compact(hop: &RouteHop) {
    let hop_number = style(format!("{:>2}", hop.hop)).blue().bold();

    match hop.address {
        Some(address) => {
            let address_text = match &hop.hostname {
                Some(hostname) => {
                    format!("{hostname} ({address})")
                }

                None => address.to_string(),
            };

            let rtt_text = match hop.stats() {
                Some(stats) => {
                    format!("{:.3} ms", stats.avg)
                }

                None => "unknown".to_string(),
            };

            println!(
                "{}  {:<45} {}",
                hop_number,
                style(address_text).cyan(),
                style(rtt_text).green().bold()
            );
        }

        None => {
            println!("{}  {}", hop_number, style("*").yellow().bold());
        }
    }
}

/// Resolve and Display Error Resonse
fn classify_network_error(error: io::Error) -> PingResult {
    match error.raw_os_error() {
        Some(code) if code == libc::ENETUNREACH => PingResult::NetworkUnreachable { from: None },

        Some(code) if code == libc::EHOSTUNREACH || code == libc::EHOSTDOWN => {
            PingResult::HostUnreachable { from: None }
        }

        Some(code) if code == libc::ENETDOWN => PingResult::NetworkDown,

        Some(code) if code == libc::EACCES || code == libc::EPERM => PingResult::PermissionDenied,

        _ => PingResult::LocalError(error.to_string()),
    }
}

fn classify_icmp_error(
    icmp_type: u8,
    icmp_code: u8,
    from: Option<Ipv4Addr>,
    info: u32,
) -> PingResult {
    match (icmp_type, icmp_code) {
        // Destination Unreachable
        (3, 0) => PingResult::NetworkUnreachable { from },

        (3, 1) => PingResult::HostUnreachable { from },

        (3, 2) => PingResult::ProtocolUnreachable { from },

        (3, 3) => PingResult::PortUnreachable { from },

        (3, 4) => PingResult::FragmentationNeeded {
            from,
            mtu: if info > 0 { Some(info) } else { None },
        },

        (3, 5) => PingResult::SourceRouteFailed { from },

        // Administratively prohibited variants
        (3, 9) | (3, 10) | (3, 13) => PingResult::AdministrativelyProhibited { from },

        // Time Exceeded
        (11, 0) | (11, 1) => PingResult::TimeExceeded { from, rtt: None },

        // Parameter Problem
        (12, _) => PingResult::ParameterProblem { from },

        _ => PingResult::IcmpError {
            from,
            icmp_type,
            icmp_code,
        },
    }
}

fn format_error_source(from: &Option<Ipv4Addr>) -> String {
    match from {
        Some(address) => format!("from={address}"),
        None => String::new(),
    }
}

fn read_error_queue(fd: i32) -> Option<QueuedIcmpError> {
    let mut data = [0u8; 512];

    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    let mut source: libc::sockaddr_in = unsafe { mem::zeroed() };

    #[repr(align(16))]
    struct ErrorControlBuffer {
        bytes: [u8; 256],
    }

    let mut control = ErrorControlBuffer { bytes: [0u8; 256] };

    let mut message: libc::msghdr = unsafe { mem::zeroed() };

    message.msg_name = &mut source as *mut libc::sockaddr_in as *mut libc::c_void;
    message.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;

    message.msg_control = control.bytes.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control.bytes.len();

    let received =
        unsafe { libc::recvmsg(fd, &mut message, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };

    if received < 0 {
        return None;
    }

    let received = received as usize;

    if received < ICMP_HEADER_SIZE {
        return None;
    }

    let sequence = u16::from_be_bytes([data[6], data[7]]);

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&message as *const libc::msghdr);

        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_RECVERR {
                let error_ptr = libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err;

                if error_ptr.is_null() {
                    return None;
                }

                let extended_error = std::ptr::read_unaligned(error_ptr);

                if extended_error.ee_origin != libc::SO_EE_ORIGIN_ICMP {
                    cmsg = libc::CMSG_NXTHDR(&message as *const libc::msghdr, cmsg);
                    continue;
                }

                let offender_ptr = libc::SO_EE_OFFENDER(error_ptr);

                let from = if !offender_ptr.is_null()
                    && (*offender_ptr).sa_family as i32 == libc::AF_INET
                {
                    let offender = &*(offender_ptr as *const libc::sockaddr_in);

                    Some(Ipv4Addr::from(offender.sin_addr.s_addr.to_ne_bytes()))
                } else {
                    None
                };

                let result = classify_icmp_error(
                    extended_error.ee_type,
                    extended_error.ee_code,
                    from,
                    extended_error.ee_info,
                );

                return Some(QueuedIcmpError { sequence, result });
            }

            cmsg = libc::CMSG_NXTHDR(&message as *const libc::msghdr, cmsg);
        }
    }

    None
}

/// End of Functions - Main
fn main() -> io::Result<()> {
    let cli = Cli::parse();

    if cli.count == Some(0) {
        eprintln!("COUNT must be greater than zero");

        std::process::exit(2);
    }

    if cli.timeout == 0 {
        eprintln!(
            "{}",
            style("TIMEOUT must be greater than zero").red().bold()
        );
        std::process::exit(2);
    }

    if cli.interval == 0 {
        eprintln!(
            "{}",
            style("INTERVAL must be greater than zero").red().bold()
        );
        std::process::exit(2);
    }

    if cli.size > MAX_PAYLOAD_SIZE {
        eprintln!(
            "{}",
            style(format!(
                "SIZE must be between 0 and {MAX_PAYLOAD_SIZE} bytes"
            ))
            .red()
            .bold()
        );
        std::process::exit(2);
    }

    let timeout = Duration::from_millis(cli.timeout);
    let interval = Duration::from_millis(cli.interval);

    if cli.broadcast {
        return run_broadcast_mode(&cli);
    }

    if cli.sweep {
        return run_sweep_mode(&cli);
    }

    let target_name = match &cli.target {
        Some(target) => target,

        None => {
            eprintln!("TARGET is required for ping and route modes");

            std::process::exit(2);
        }
    };

    let target = match resolve_target(target_name) {
        Ok(ip) => ip,

        Err(error) => {
            eprintln!(
                "{} {}: {}",
                style("DNS Failure").red().bold(),
                target_name,
                error
            );

            std::process::exit(2);
        }
    };

    let target_display = display_target(target_name, target);

    let fd = match create_ping_socket(timeout) {
        Ok(fd) => fd,

        Err(error) => {
            eprintln!("ring: unable to create ICMP ping socket: {}", error);

            eprintln!("Check: sysctl net.ipv4.ping_group_range");

            std::process::exit(3);
        }
    };

    let running = Arc::new(AtomicBool::new(true));

    let handler_running = Arc::clone(&running);

    ctrlc::set_handler(move || {
        handler_running.store(false, Ordering::SeqCst);
    })
    .expect("Unable to install Ctrl+C handler");

    let requested_count = cli.count.unwrap_or(1);

    let show_statistics = cli.continuous || cli.count.is_some();

    let mut attempts: u32 = 0;

    let mut sequence: u16 = 1;

    let mut stats = PingStats::new();

    let mut json_probes: Vec<JsonPingProbe> = Vec::new();

    if cli.route {
        let result = run_route_mode(fd, target, &target_display, &cli);

        unsafe {
            libc::close(fd);
        }

        return result;
    }

    while running.load(Ordering::SeqCst) {
        if !cli.continuous && attempts >= requested_count {
            break;
        }

        attempts += 1;

        let packet = build_echo_request(sequence, cli.size);

        let start = Instant::now();

        let result = match send_echo_request(fd, target, &packet) {
            Ok(()) => {
                stats.transmitted += 1;

                wait_for_reply(fd, target, sequence, start)
            }

            Err(error) => classify_network_error(error),
        };

        if cli.json {
            json_probes.push(ping_result_to_json(sequence, &result));
        } else {
            print_result(&target_display, sequence, &result, timeout);
        }

        match &result {
            PingResult::Alive { rtt, ttl } => {
                stats.record_reply(*rtt, *ttl);
            }

            PingResult::NoResponse => {}

            _ => stats.errors += 1,
        }

        sequence = sequence.wrapping_add(1);

        if !cli.continuous && attempts >= requested_count {
            break;
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }

        thread::sleep(interval);
    }

    unsafe { libc::close(fd) };

    if cli.json {
        let output = JsonPingOutput {
            schema_version: 1,
            mode: "ping",
            target: target_name.clone(),
            address: target,
            transmitted: stats.transmitted,
            received: stats.received,
            probes: json_probes,
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("Unable to serialize JSON output")
        );
    } else if show_statistics {
        stats.print(&target_display);
    }

    if stats.received == 0 {
        std::process::exit(1);
    }

    Ok(())
}
