use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct PingStats {
    pub transmitted: u32,
    pub received: u32,
    pub errors: u32,
    pub rtts: Vec<Duration>,
    pub ttls: Vec<u8>,
    pub started: Instant,
}

pub struct QueuedIcmpError {
    pub sequence: u16,
    pub result: PingResult,
}

pub struct RouteHop {
    pub hop: u8,
    pub address: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub rtts: Vec<Duration>,
    pub probes_sent: u32,
    pub reached_destination: bool,
    pub multiple_responders: bool,
}

#[derive(Debug)]
pub struct RttStats {
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub mdev: f64,
}

#[derive(Debug)]
pub struct Ipv4Interface {
    pub name: String,
    pub address: Ipv4Addr,
    pub network: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub prefix_length: u8,
}

#[derive(Debug)]
pub struct SweepRange {
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub network: Option<Ipv4Addr>,
    pub prefix_length: Option<u8>,
    pub interface_name: Option<String>,
}

pub struct SweepProbe {
    pub target: Ipv4Addr,
    pub sequence: u16,
    pub sent_at: Instant,
}

pub enum PingResult {
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

pub enum SweepEvent {
    Reply { source: Ipv4Addr, sequence: u16 },
}
