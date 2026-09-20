use std::mem;
use std::net::Ipv4Addr;

pub fn reverse_dns(address: Ipv4Addr) -> Option<String> {
    let socket_address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    };

    let mut hostname = [0i8; libc::NI_MAXHOST as usize];

    let result = unsafe {
        libc::getnameinfo(
            &socket_address as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            hostname.as_mut_ptr(),
            hostname.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };

    if result != 0 {
        return None;
    }

    let hostname = unsafe { std::ffi::CStr::from_ptr(hostname.as_ptr()) };

    Some(hostname.to_string_lossy().into_owned())
}
