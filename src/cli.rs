use clap::Parser;
use std::net::Ipv4Addr;

use crate::constants::{DEFAULT_PAYLOAD_SIZE, DEFAULT_SWEEP_CONCURRENCY};

#[derive(Parser, Debug)]
#[command(
    name = "ring",
    version,
    about = "Linux ICMP reachability, latency, route tracing, and network discovery utility"
)]
pub struct Cli {
    #[arg(short = 'c', long, value_name = "COUNT")]
    pub count: Option<u32>,

    #[arg(short = 'z', long, conflicts_with = "count")]
    pub continuous: bool,

    /// Probe local IPv4 broadcast addresses
    #[arg(
        short = 'b',
        long,
        conflicts_with_all = ["route", "sweep", "json"]
    )]
    pub broadcast: bool,

    /// ICMP payload size in bytes
    #[arg(
        short = 's',
        long = "size",
        value_name = "BYTES",
        default_value_t = DEFAULT_PAYLOAD_SIZE
    )]
    pub size: usize,

    /// Reply timeout in milliseconds
    #[arg(short = 't', long, value_name = "MILLISECONDS")]
    pub timeout: Option<u64>,

    /// Delay between transmitted requests in milliseconds
    #[arg(short = 'i', long = "interval", value_name = "MILLISECONDS")]
    pub interval: Option<u64>,

    /// Host/IP normally, or interface name when -b is used
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Trace the route to the destination
    #[arg(
        long,
        conflicts_with_all = ["broadcast", "sweep", "json"]
    )]
    pub route: bool,

    /// Perform reverse DNS lookups for route hops
    #[arg(long, requires = "route")]
    pub resolve: bool,

    /// Display detailed route information
    #[arg(short = 'v', long, requires = "route")]
    pub verbose: bool,

    /// Maximum number of hops when tracing a route
    #[arg(long = "max-hops", value_name = "HOPS", default_value_t = 30)]
    pub max_hops: u8,

    /// Sweep IPv4 addresses for responding hosts
    #[arg(
        short = 'S',
        long,
        conflicts_with_all = ["broadcast", "route", "json"]
    )]
    pub sweep: bool,

    /// Maximum number of outstanding sweep probes
    #[arg(
        long = "concurrency",
        value_name = "COUNT",
        default_value_t = DEFAULT_SWEEP_CONCURRENCY,
        requires = "sweep"
    )]
    pub concurrency: usize,

    /// Automatically confirm permitted large RFC1918 private-network sweeps
    #[arg(short = 'y', long = "yes", requires = "sweep")]
    pub yes: bool,

    /// Force a sweep regardless of network size or public/private address space
    #[arg(long, requires = "sweep")]
    pub force: bool,

    /// First IPv4 address in a manually specified sweep range
    #[arg(
        long,
        value_name = "ADDRESS",
        requires = "sweep",
        requires = "high",
        conflicts_with = "network"
    )]
    pub low: Option<Ipv4Addr>,

    /// Last IPv4 address in a manually specified sweep range
    #[arg(
        long,
        value_name = "ADDRESS",
        requires = "sweep",
        requires = "low",
        conflicts_with = "network"
    )]
    pub high: Option<Ipv4Addr>,

    /// IPv4 network to sweep
    #[arg(
        long,
        value_name = "NETWORK",
        requires = "sweep",
        conflicts_with_all = ["low", "high"]
    )]
    pub network: Option<String>,

    /// Subnet mask used with --network
    #[arg(long, value_name = "NETMASK", requires = "network")]
    pub mask: Option<Ipv4Addr>,

    /// Output structured results as JSON
    #[arg(long)]
    pub json: bool,
}
