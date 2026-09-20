mod cli;
mod constants;
mod dns;
mod ipv4;
mod ipv6;
mod json;
mod modes;
mod output;
mod stats;
mod types;

use clap::Parser;
use console::style;

use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::cli::Cli;

use crate::constants::{
    DEFAULT_INTERVAL_MILLISECONDS, DEFAULT_SWEEP_INTERVAL_MILLISECONDS,
    DEFAULT_SWEEP_TIMEOUT_MILLISECONDS, DEFAULT_TIMEOUT_MILLISECONDS, MAX_PAYLOAD_SIZE,
};

use crate::output::display_target;

fn effective_timeout(cli: &Cli) -> Duration {
    let milliseconds = cli.timeout.unwrap_or(if cli.sweep {
        DEFAULT_SWEEP_TIMEOUT_MILLISECONDS
    } else {
        DEFAULT_TIMEOUT_MILLISECONDS
    });

    Duration::from_millis(milliseconds)
}

fn effective_interval(cli: &Cli) -> Duration {
    let milliseconds = cli.interval.unwrap_or(if cli.sweep {
        DEFAULT_SWEEP_INTERVAL_MILLISECONDS
    } else {
        DEFAULT_INTERVAL_MILLISECONDS
    });

    Duration::from_millis(milliseconds)
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

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    /*
     * General CLI validation
     */

    if cli.count == Some(0) {
        eprintln!("{}", style("COUNT must be greater than zero").red().bold());

        std::process::exit(2);
    }

    if cli.timeout == Some(0) {
        eprintln!(
            "{}",
            style("TIMEOUT must be greater than zero").red().bold()
        );

        std::process::exit(2);
    }

    if cli.interval == Some(0) {
        eprintln!(
            "{}",
            style("INTERVAL must be greater than zero").red().bold()
        );

        std::process::exit(2);
    }

    if cli.concurrency == 0 {
        eprintln!(
            "{}",
            style("CONCURRENCY must be greater than zero").red().bold()
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

    /*
     * Establish mode timing.
     */

    let timeout = effective_timeout(&cli);

    let interval = effective_interval(&cli);

    /*
     * Modes that do not require
     * destination resolution.
     */

    if cli.broadcast {
        return modes::broadcast::run(&cli);
    }

    if cli.sweep {
        return modes::sweep::run(&cli, timeout, interval);
    }

    /*
     * Ping and route require
     * a destination.
     */

    let target_name = match &cli.target {
        Some(target) => target,

        None => {
            eprintln!(
                "{}",
                style("TARGET is required for ping and route modes")
                    .red()
                    .bold()
            );

            std::process::exit(2);
        }
    };

    /*
     * Resolve target to IPv4.
     */

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

    /*
     * Route mode.
     */

    if cli.route {
        return modes::route::run(&cli, target, &target_display, timeout);
    }

    /*
     * Normal ping mode.
     */

    modes::ping::run(
        &cli,
        target_name,
        target,
        &target_display,
        timeout,
        interval,
    )
}
