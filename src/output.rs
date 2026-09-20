use console::style;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::stats::estimate_hops;
use crate::types::{PingResult, RouteHop};

pub fn display_target(original: &str, resolved: Ipv4Addr) -> String {
    if original.parse::<Ipv4Addr>().is_ok() {
        resolved.to_string()
    } else {
        format!("{original} ({resolved})")
    }
}

pub fn print_result(target: &str, sequence: u16, result: &PingResult, timeout: Duration) {
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

pub fn print_route_statistics(hop: &RouteHop, previous_average: &mut Option<f64>) {
    let address_text = match hop.address {
        Some(address) => match &hop.hostname {
            Some(hostname) => format!("{hostname} ({address})"),
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

pub fn print_route_compact(hop: &RouteHop) {
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

pub fn format_error_source(from: &Option<Ipv4Addr>) -> String {
    match from {
        Some(address) => format!("from={address}"),
        None => String::new(),
    }
}
