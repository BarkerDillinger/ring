use std::io;
use std::net::Ipv4Addr;

use crate::types::{Ipv4Interface, SweepRange};

pub fn get_ipv4_interfaces(requested_interface: Option<&str>) -> io::Result<Vec<Ipv4Interface>> {
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut interfaces = Vec::new();

    let mut current = ifaddrs;

    while !current.is_null() {
        let interface = unsafe { &*current };

        if !interface.ifa_addr.is_null()
            && unsafe { (*interface.ifa_addr).sa_family as i32 == libc::AF_INET }
        {
            let flags = interface.ifa_flags as i32;

            let is_up = flags & libc::IFF_UP != 0;

            let supports_broadcast = flags & libc::IFF_BROADCAST != 0;

            let is_loopback = flags & libc::IFF_LOOPBACK != 0;

            if is_up && supports_broadcast && !is_loopback {
                let name = unsafe { std::ffi::CStr::from_ptr(interface.ifa_name) }
                    .to_string_lossy()
                    .into_owned();

                if requested_interface.is_none_or(|requested| requested == name) {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in) };

                    let netmask = unsafe { &*(interface.ifa_netmask as *const libc::sockaddr_in) };

                    let ip = u32::from_be_bytes(address.sin_addr.s_addr.to_ne_bytes());

                    let mask = u32::from_be_bytes(netmask.sin_addr.s_addr.to_ne_bytes());

                    let network = ip & mask;

                    let broadcast = ip | !mask;

                    let prefix_length = mask.count_ones() as u8;

                    interfaces.push(Ipv4Interface {
                        name,
                        address: Ipv4Addr::from(ip),

                        network: Ipv4Addr::from(network),

                        broadcast: Ipv4Addr::from(broadcast),

                        prefix_length,
                    });
                }
            }
        }

        current = unsafe { (*current).ifa_next };
    }

    unsafe {
        libc::freeifaddrs(ifaddrs);
    }

    Ok(interfaces)
}

pub fn prefix_from_netmask(mask: Ipv4Addr) -> Option<u8> {
    let mask = u32::from(mask);

    let inverted = !mask;

    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }

    Some(mask.count_ones() as u8)
}

pub fn range_from_interface(interface: &Ipv4Interface) -> io::Result<SweepRange> {
    if interface.prefix_length >= 31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{}/{} is not supported for sweep mode",
                interface.network, interface.prefix_length
            ),
        ));
    }

    let network = u32::from(interface.network);

    let broadcast = u32::from(interface.broadcast);

    Ok(SweepRange {
        first: Ipv4Addr::from(network + 1),

        last: Ipv4Addr::from(broadcast - 1),

        network: Some(interface.network),

        prefix_length: Some(interface.prefix_length),

        interface_name: Some(interface.name.clone()),
    })
}

pub fn range_from_low_high(low: Ipv4Addr, high: Ipv4Addr) -> io::Result<SweepRange> {
    if u32::from(low) > u32::from(high) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LOW address must not be greater than HIGH address",
        ));
    }

    Ok(SweepRange {
        first: low,
        last: high,
        network: None,
        prefix_length: None,
        interface_name: None,
    })
}

pub fn range_from_network_mask(address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<SweepRange> {
    let prefix_length = prefix_from_netmask(mask).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{mask} is not a valid contiguous IPv4 subnet mask"),
        )
    })?;

    if prefix_length >= 31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "/31 and /32 networks are not supported for sweep mode",
        ));
    }

    let address_value = u32::from(address);

    let mask_value = u32::from(mask);

    let network = address_value & mask_value;

    let broadcast = network | !mask_value;

    Ok(SweepRange {
        first: Ipv4Addr::from(network + 1),

        last: Ipv4Addr::from(broadcast - 1),

        network: Some(Ipv4Addr::from(network)),

        prefix_length: Some(prefix_length),

        interface_name: None,
    })
}

pub fn range_from_cidr(cidr: &str) -> io::Result<SweepRange> {
    let (address_text, prefix_text) = cidr.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "CIDR must be written as ADDRESS/PREFIX",
        )
    })?;

    let address: Ipv4Addr = address_text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid IPv4 address: {address_text}"),
        )
    })?;

    let prefix: u8 = prefix_text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid prefix length: {prefix_text}"),
        )
    })?;

    if prefix > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 prefix length must be between 0 and 32",
        ));
    }

    if prefix >= 31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "/31 and /32 networks are not supported for sweep mode",
        ));
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    range_from_network_mask(address, Ipv4Addr::from(mask))
}

pub fn range_is_rfc1918(range: &SweepRange) -> bool {
    let first = u32::from(range.first);

    let last = u32::from(range.last);

    let private_ranges = [
        (
            u32::from(Ipv4Addr::new(10, 0, 0, 0)),
            u32::from(Ipv4Addr::new(10, 255, 255, 255)),
        ),
        (
            u32::from(Ipv4Addr::new(172, 16, 0, 0)),
            u32::from(Ipv4Addr::new(172, 31, 255, 255)),
        ),
        (
            u32::from(Ipv4Addr::new(192, 168, 0, 0)),
            u32::from(Ipv4Addr::new(192, 168, 255, 255)),
        ),
    ];

    private_ranges
        .iter()
        .any(|(start, end)| first >= *start && last <= *end)
}

pub fn sweep_range_size(range: &SweepRange) -> u64 {
    let first = u32::from(range.first) as u64;

    let last = u32::from(range.last) as u64;

    last - first + 1
}
