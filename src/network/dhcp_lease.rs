use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};
use pnet::datalink::MacAddr;
use crate::network::config::{LEASE_DURATION, STARTING_CLIENT_IP};

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub(crate) ip_address: Ipv4Addr,
    lease_duration: Duration,
    lease_start: SystemTime,
}

pub struct DhcpServerState {
    leases: HashMap<MacAddr, DhcpLease>,
}

impl DhcpServerState {
    pub fn new() -> Self {
        DhcpServerState {
            leases: HashMap::new(),
        }
    }

    pub fn add_lease(&mut self, client_mac: MacAddr, ip_address: Ipv4Addr) {
        let lease = DhcpLease {
            ip_address,
            lease_duration: Duration::from_secs(LEASE_DURATION),
            lease_start: SystemTime::now(),
        };
        self.leases.insert(client_mac, lease);
    }

    pub fn get_lease(&self, client_mac: &MacAddr) -> Option<&DhcpLease> {
        self.leases.get(client_mac)
    }

    pub fn expire_leases(&mut self) {
        let now = SystemTime::now();
        self.leases.retain(|_, lease| lease.lease_start + lease.lease_duration > now);
    }

    pub fn find_free_ip(&self) -> Option<Ipv4Addr> {
        let mut ip = STARTING_CLIENT_IP;
        while ip <= Ipv4Addr::new(192, 168, 1, 254) {
            if !self.leases.values().any(|lease| lease.ip_address == ip) {
                return Some(ip);
            }
            ip = increment_ip(ip);
        }
        None
    }
}

fn increment_ip(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    let num = u32::from_be_bytes(octets) + 1;
    Ipv4Addr::from(num.to_be_bytes())
}