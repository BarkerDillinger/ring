use console::style;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::Cli;

use crate::ipv4::errors::classify_network_error;

use crate::ipv4::interface::{
    get_ipv4_interfaces, range_from_cidr, range_from_interface, range_from_low_high,
    range_from_network_mask, range_is_rfc1918, sweep_range_size,
};

use crate::ipv4::packet::build_echo_request;

use crate::ipv4::socket::{
    create_ping_socket, receive_sweep_reply, send_echo_request, set_socket_nonblocking,
};

use crate::types::{SweepEvent, SweepProbe, SweepRange};

fn sweep_range(
    fd: i32,
    range: &SweepRange,
    payload_size: usize,
    timeout: Duration,
    interval: Duration,
    concurrency: usize,
) -> io::Result<()> {
    let mut next_address = u32::from(range.first);

    let last_address = u32::from(range.last);

    let mut sequence: u16 = 1;

    let mut outstanding: Vec<SweepProbe> = Vec::new();

    let mut next_send = Instant::now();

    while next_address <= last_address || !outstanding.is_empty() {
        while next_address <= last_address
            && outstanding.len() < concurrency
            && Instant::now() >= next_send
        {
            let target = Ipv4Addr::from(next_address);

            let packet = build_echo_request(sequence, payload_size);

            match send_echo_request(fd, target, &packet) {
                Ok(()) => {
                    outstanding.push(SweepProbe {
                        target,
                        sequence,
                        sent_at: Instant::now(),
                    });
                }

                Err(error) => {
                    match error.kind() {
                        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                            /*
                             * A queued ICMP error from an
                             * earlier sweep probe can surface
                             * on sendto().
                             *
                             * It does not reliably identify
                             * the current target, so keep
                             * normal sweep output silent.
                             */
                        }

                        _ => {
                            let result = classify_network_error(error);

                            if let crate::types::PingResult::LocalError(message) = result {
                                eprintln!(
                                    "{}",
                                    style(format!("ring: {target}: {message}")).red().bold()
                                );
                            }
                        }
                    }
                }
            }

            next_address += 1;

            sequence = sequence.wrapping_add(1);

            next_send = Instant::now() + interval;
        }

        while let Some(event) = receive_sweep_reply(fd)? {
            match event {
                SweepEvent::Reply { source, sequence } => {
                    if let Some(index) = outstanding
                        .iter()
                        .position(|probe| probe.sequence == sequence && probe.target == source)
                    {
                        println!("{source}");

                        outstanding.swap_remove(index);
                    }
                }
            }
        }

        let now = Instant::now();

        outstanding.retain(|probe| now.duration_since(probe.sent_at) < timeout);

        thread::sleep(Duration::from_millis(1));
    }

    Ok(())
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
            "{}",
            style(format!(
                "ring: {} - {} is not entirely within RFC1918 private address space",
                range.first, range.last
            ))
            .red()
            .bold()
        );

        eprintln!(
            "{}",
            style("Use --force to authorize sweeping non-private address space.").yellow()
        );

        return Ok(false);
    }

    if count <= 254 {
        return Ok(true);
    }

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
                Some(name) => {
                    format!("No usable IPv4 interface named {name}")
                }

                None => "No usable IPv4 interfaces found".to_string(),
            },
        ));
    }

    interfaces.iter().map(range_from_interface).collect()
}

pub fn run(cli: &Cli, timeout: Duration, interval: Duration) -> io::Result<()> {
    let ranges = build_sweep_ranges(cli)?;

    let fd = create_ping_socket(timeout)?;

    set_socket_nonblocking(fd)?;

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

        sweep_range(fd, range, cli.size, timeout, interval, cli.concurrency)?;
    }

    unsafe {
        libc::close(fd);
    }

    Ok(())
}
