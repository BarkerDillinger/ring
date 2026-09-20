use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::ipv4::constants::{ICMP_ECHO_REPLY, ICMP_HEADER_SIZE};

use crate::types::{PingResult, SweepEvent};

// These will come from ipv4/errors.rs,
// which we will build next.
use crate::ipv4::errors::{classify_network_error, read_error_queue};

#[derive(Debug)]
#[repr(align(16))]
struct ControlBuffer {
    bytes: [u8; 64],
}

pub fn create_ping_socket(timeout: Duration) -> io::Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let timeout = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();

        unsafe {
            libc::close(fd);
        }

        return Err(error);
    }

    let enable_ttl: libc::c_int = 1;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            &enable_ttl as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();

        unsafe {
            libc::close(fd);
        }

        return Err(error);
    }

    let enable_errors: libc::c_int = 1;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            &enable_errors as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();

        unsafe {
            libc::close(fd);
        }

        return Err(error);
    }

    Ok(fd)
}

pub fn set_socket_ttl(fd: i32, ttl: u8) -> io::Result<()> {
    let ttl_value: libc::c_int = ttl as libc::c_int;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl_value as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn send_echo_request(fd: i32, target: Ipv4Addr, packet: &[u8]) -> io::Result<()> {
    let destination = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,

        sin_port: 0,

        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(target.octets()),
        },

        sin_zero: [0; 8],
    };

    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &destination as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    if sent as usize != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "Incomplete ICMP packet transmission",
        ));
    }

    Ok(())
}

pub fn wait_for_reply(fd: i32, target: Ipv4Addr, sequence: u16, start: Instant) -> PingResult {
    let mut buffer = [0u8; 65_535];

    loop {
        let mut source: libc::sockaddr_in = unsafe { mem::zeroed() };

        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };

        let mut control = ControlBuffer { bytes: [0u8; 64] };

        let mut message: libc::msghdr = unsafe { mem::zeroed() };

        message.msg_name = &mut source as *mut libc::sockaddr_in as *mut libc::c_void;

        message.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;

        message.msg_control = control.bytes.as_mut_ptr() as *mut libc::c_void;

        message.msg_controllen = control.bytes.len();

        let received = unsafe { libc::recvmsg(fd, &mut message, 0) };

        if received < 0 {
            let error = io::Error::last_os_error();

            /*
             * Before treating the socket error as a timeout
             * or local failure, inspect Linux's extended
             * socket error queue.
             */
            if let Some(queued_error) = read_error_queue(fd) {
                if queued_error.sequence != sequence {
                    continue;
                }

                let mut network_error = queued_error.result;

                if let PingResult::TimeExceeded { rtt, .. } = &mut network_error {
                    *rtt = Some(start.elapsed());
                }

                return network_error;
            }

            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PingResult::NoResponse,

                _ => classify_network_error(error),
            };
        }

        let packet = &buffer[..received as usize];

        if packet.len() < ICMP_HEADER_SIZE {
            continue;
        }

        let source_ip = Ipv4Addr::from(source.sin_addr.s_addr.to_ne_bytes());

        if source_ip != target {
            continue;
        }

        let icmp_type = packet[0];
        let icmp_code = packet[1];

        if icmp_type != ICMP_ECHO_REPLY || icmp_code != 0 {
            continue;
        }

        let reply_sequence = u16::from_be_bytes([packet[6], packet[7]]);

        if reply_sequence != sequence {
            continue;
        }

        let ttl = extract_ttl(&message);

        return PingResult::Alive {
            rtt: start.elapsed(),
            ttl,
        };
    }
}

pub fn set_socket_nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };

    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn receive_sweep_reply(fd: i32) -> io::Result<Option<SweepEvent>> {
    let mut buffer = [0u8; 65_535];

    let mut source: libc::sockaddr_in = unsafe { mem::zeroed() };

    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut libc::c_void,

        iov_len: buffer.len(),
    };

    let mut message: libc::msghdr = unsafe { mem::zeroed() };

    message.msg_name = &mut source as *mut libc::sockaddr_in as *mut libc::c_void;

    message.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;

    let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };

    if received < 0 {
        let error = io::Error::last_os_error();

        return match error.kind() {
            io::ErrorKind::WouldBlock
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable => Ok(None),

            _ => Err(error),
        };
    }

    let received = received as usize;

    if received < ICMP_HEADER_SIZE {
        return Ok(None);
    }

    if buffer[0] != ICMP_ECHO_REPLY || buffer[1] != 0 {
        return Ok(None);
    }

    let sequence = u16::from_be_bytes([buffer[6], buffer[7]]);

    let source = Ipv4Addr::from(source.sin_addr.s_addr.to_ne_bytes());

    Ok(Some(SweepEvent::Reply { source, sequence }))
}

fn extract_ttl(message: &libc::msghdr) -> Option<u8> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(message as *const libc::msghdr);

        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_TTL {
                let ttl_ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;

                let ttl = std::ptr::read_unaligned(ttl_ptr);

                return u8::try_from(ttl).ok();
            }

            cmsg = libc::CMSG_NXTHDR(message as *const libc::msghdr, cmsg);
        }
    }

    None
}
