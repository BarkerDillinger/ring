use crate::ipv4::constants::{ICMP_ECHO_REQUEST, ICMP_HEADER_SIZE};

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let (chunks, remainder) = data.as_chunks::<2>();

    for chunk in chunks {
        let word = u16::from_be_bytes(*chunk);
        sum += word as u32;
    }

    if let Some(&byte) = remainder.first() {
        sum += (byte as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

pub fn build_echo_request(sequence: u16, payload_size: usize) -> Vec<u8> {
    let mut packet = vec![0u8; ICMP_HEADER_SIZE + payload_size];

    packet[0] = ICMP_ECHO_REQUEST;
    packet[1] = 0;

    packet[2] = 0;
    packet[3] = 0;

    packet[4] = 0;
    packet[5] = 0;

    packet[6..8].copy_from_slice(&sequence.to_be_bytes());

    for (i, byte) in packet[ICMP_HEADER_SIZE..].iter_mut().enumerate() {
        *byte = (i & 0xff) as u8;
    }

    let csum = checksum(&packet);

    packet[2..4].copy_from_slice(&csum.to_be_bytes());

    packet
}
