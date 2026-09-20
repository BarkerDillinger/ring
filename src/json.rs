use serde::Serialize;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::types::PingResult;

#[derive(Serialize)]
pub struct JsonPingProbe {
    pub sequence: u16,
    pub status: JsonStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Ipv4Addr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct JsonPingOutput {
    pub schema_version: u32,
    pub mode: &'static str,
    pub target: String,
    pub address: Ipv4Addr,
    pub transmitted: u32,
    pub received: u32,
    pub probes: Vec<JsonPingProbe>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonStatus {
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

pub fn duration_ms(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 1_000_000.0).round() / 1_000.0
}

pub fn ping_result_to_json(sequence: u16, result: &PingResult) -> JsonPingProbe {
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
