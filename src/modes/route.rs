use console::style;
use std::io;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::cli::Cli;

use crate::dns::reverse_dns;

use crate::ipv4::errors::classify_network_error;

use crate::ipv4::packet::build_echo_request;

use crate::ipv4::socket::{create_ping_socket, send_echo_request, set_socket_ttl, wait_for_reply};

use crate::output::{print_route_compact, print_route_statistics};

use crate::types::{PingResult, RouteHop};

fn route_probe_count(cli: &Cli) -> u32 {
    match cli.count {
        Some(count) => count,

        None if cli.verbose => 3,

        None => 1,
    }
}

pub fn run(
    cli: &Cli,
    target: Ipv4Addr,
    target_display: &str,
    timeout: std::time::Duration,
) -> io::Result<()> {
    let fd = create_ping_socket(timeout)?;

    let result = run_route(fd, target, target_display, cli);

    unsafe {
        libc::close(fd);
    }

    result
}

fn run_route(fd: i32, target: Ipv4Addr, target_display: &str, cli: &Cli) -> io::Result<()> {
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
