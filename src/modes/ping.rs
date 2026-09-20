use std::io;
use std::net::Ipv4Addr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::Cli;

use crate::ipv4::errors::classify_network_error;
use crate::ipv4::packet::build_echo_request;
use crate::ipv4::socket::{create_ping_socket, send_echo_request, wait_for_reply};

use crate::json::{JsonPingOutput, JsonPingProbe, ping_result_to_json};

use crate::output::print_result;

use crate::types::{PingResult, PingStats};

pub fn run(
    cli: &Cli,
    target_name: &str,
    target: Ipv4Addr,
    target_display: &str,
    timeout: Duration,
    interval: Duration,
) -> io::Result<()> {
    let fd = match create_ping_socket(timeout) {
        Ok(fd) => fd,

        Err(error) => {
            eprintln!("ring: unable to create ICMP ping socket: {error}");

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
            print_result(target_display, sequence, &result, timeout);
        }

        match &result {
            PingResult::Alive { rtt, ttl } => {
                stats.record_reply(*rtt, *ttl);
            }

            PingResult::NoResponse => {}

            _ => {
                stats.errors += 1;
            }
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

    unsafe {
        libc::close(fd);
    }

    if cli.json {
        let output = JsonPingOutput {
            schema_version: 1,
            mode: "ping",
            target: target_name.to_string(),
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
        stats.print(target_display);
    }

    if stats.received == 0 {
        std::process::exit(1);
    }

    Ok(())
}
