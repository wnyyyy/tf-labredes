use std::net::Ipv4Addr;

pub const INTERFACE_NAME: &str = "veth0";
pub const SERVER_MAC_ADDRESS: [u8; 6] = [0x55, 0x6C, 0x2A, 0x23, 0x53, 0x65];
pub const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 109, 1);
pub const BROADCAST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 255);
pub const LEASE_DURATION: u64 = 3600;
pub const STARTING_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 110);

pub const DNS_SERVERS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(192, 168, 109, 1),
    Ipv4Addr::new(8, 8, 8, 8)
];