use std::io;
use std::mem;
use std::net::Ipv4Addr;

use crate::ipv4::constants::ICMP_HEADER_SIZE;

use crate::types::{PingResult, QueuedIcmpError};

pub fn classify_network_error(error: io::Error) -> PingResult {
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

pub fn read_error_queue(fd: i32) -> Option<QueuedIcmpError> {
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
