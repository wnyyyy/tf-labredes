// Conforme em
// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml

#[derive(Debug, Clone)]
pub enum DhcpOption {
    DhcpMsgType(DhcpMessageType),
    SubnetMask([u8; 4]),
    Router([u8; 4]),
    DomainNameServer(Vec<[u8; 4]>),
    IPAddressLeaseTime(u32),
    ServerIdentifier([u8; 4]),
    End,
}

impl DhcpOption {
    pub fn serialize(&self) -> Option<(u8, u8, Vec<u8>)> {
        match self {
            DhcpOption::DhcpMsgType(msg_type) => Some((53, 1, vec![msg_type.clone() as u8])),
            DhcpOption::IPAddressLeaseTime(time) => Some((51, 4, time.to_be_bytes().to_vec())),
            DhcpOption::SubnetMask(mask) => Some((1, 4, mask.to_vec())),
            DhcpOption::Router(router) => Some((3, 4, router.to_vec())),
            DhcpOption::DomainNameServer(servers) => {
                let mut data = Vec::new();
                for server in servers {
                    data.extend_from_slice(server);
                }
                Some((6, data.len() as u8, data))
            },
            DhcpOption::End => Some((255, 0, vec![])),
            _ => None,
        }
    }
    
    pub fn deserialize(option_code: u8, length: u8, data: &[u8]) -> Option<Self> {
        match option_code {
            53 => data.first().and_then(|&b| DhcpMessageType::from_byte(b).map(DhcpOption::DhcpMsgType)),
            1 => {
                if length == 4 && data.len() == 4 {
                    Some(DhcpOption::SubnetMask(data.try_into().unwrap()))
                } else {
                    None
                }
            },
            3 => {
                if length == 4 && data.len() == 4 {
                    Some(DhcpOption::Router(data.try_into().unwrap()))
                } else {
                    None
                }
            },
            6 => {
                let mut servers = vec![];
                for chunk in data.chunks(4) {
                    if chunk.len() == 4 {
                        servers.push(chunk.try_into().unwrap());
                    }
                }
                Some(DhcpOption::DomainNameServer(servers))
            },
            51 => {
                if length == 4 && data.len() == 4 {
                    Some(DhcpOption::IPAddressLeaseTime(u32::from_be_bytes(data.try_into().unwrap())))
                } else {
                    None
                }
            },
            54 => {
                if length == 4 && data.len() == 4 {
                    Some(DhcpOption::ServerIdentifier(data.try_into().unwrap()))
                } else {
                    None
                }
            },
            255 => Some(DhcpOption::End),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Acknowledgement = 5,
}

impl DhcpMessageType {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            5 => Some(Self::Acknowledgement),
            _ => None,
        }
    }
}
