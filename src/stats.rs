use console::style;
use std::time::Duration;

use crate::types::{PingStats, RouteHop, RttStats};

impl PingStats {
    pub fn new() -> Self {
        Self {
            transmitted: 0,
            received: 0,
            errors: 0,
            rtts: Vec::new(),
            ttls: Vec::new(),
            started: std::time::Instant::now(),
        }
    }

    pub fn record_reply(&mut self, rtt: Duration, ttl: Option<u8>) {
        self.received += 1;
        self.rtts.push(rtt);

        if let Some(ttl) = ttl {
            self.ttls.push(ttl);
        }
    }

    pub fn print(&self, target: &str) {
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
    pub fn responses(&self) -> usize {
        self.rtts.len()
    }

    pub fn response_loss(&self) -> f64 {
        if self.probes_sent == 0 {
            return 0.0;
        }

        let lost = self.probes_sent as usize - self.responses();

        lost as f64 / self.probes_sent as f64 * 100.0
    }

    pub fn stats(&self) -> Option<RttStats> {
        calculate_rtt_stats(&self.rtts)
    }
}

pub fn estimate_hops(ttl: u8) -> u8 {
    let assumed_initial_ttl = match ttl {
        0..=64 => 64,
        65..=128 => 128,
        _ => 255,
    };

    assumed_initial_ttl - ttl
}

pub fn calculate_rtt_stats(rtts: &[Duration]) -> Option<RttStats> {
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
