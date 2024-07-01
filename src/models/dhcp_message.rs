// Estrutura das mensagens DHCP conforme definida em
// https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042653.htm

use crate::models::dhcp_option::{DhcpMessageType, DhcpOption};

#[derive(Debug, Clone)]
pub struct DhcpMessage {
    op: u8,          // Message type defined in option field. 1 = REQUEST, 2 = REPLY
    htype: u8,       // Hardware address type and length of a DHCP client.
    hlen: u8,
    hops: u8,        // Number of relay agents a request message traveled.
    pub(crate) xid: u32,        // Transaction ID, a random number chosen by the client to identify an IP address allocation
    secs: u16,       // Filled in by the client, the number of seconds elapsed since the client began address acquisition or renewal process. Currently, this field is reserved and set to 0.
    flags: u16,      // The leftmost bit is defined as the BROADCAST (B) flag. If this flag is set to 0, the DHCP server sent a reply back by unicast;
                     // if this flag is set to 1, the DHCP server sent a reply back by broadcast. The remaining bits of the flags field are reserved for future use.
    pub(crate) ciaddr: [u8; 4], // Client IP address.
    yiaddr: [u8; 4], // 'your' (client) IP address, assigned by the server.
    siaddr: [u8; 4], // Server IP address, from which the client obtained configuration parameters.
    giaddr: [u8; 4], // IP address of the first relay agent a request message traveled.
    pub(crate) chaddr: [u8; 16],// Client hardware address.
    sname: [u8; 64], // Server host name, from which the client obtained configuration parameters.\
    file: [u8; 128], // Bootfile name and path information, defined by the server to the client.
    options: Vec<DhcpOption>, // Optional parameters field that is variable in length, which includes the message type, lease, domain name server IP address, and WINS IP address.
}

#[allow(clippy::too_many_arguments)]
impl DhcpMessage {
    pub fn new(
        op: u8, htype: u8, hlen: u8, hops: u8,
        xid: u32, secs: u16, flags: u16,
        ciaddr: [u8; 4], yiaddr: [u8; 4],
        siaddr: [u8; 4], giaddr: [u8; 4],
        chaddr: [u8; 16], sname: [u8; 64],
        file: [u8; 128], options: Vec<DhcpOption>
    ) -> Self {
        DhcpMessage {
            op, htype, hlen, hops, xid, secs, flags,
            ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, options
        }
    }

    pub fn total_size(&self) -> usize {
        let fixed_size = 240;
        let options_size: usize = self.options.iter().map(|opt| {
            if let Some((_, _, data)) = opt.serialize() {
                2 + data.len()
            } else {
                0
            }
        }).sum();

        fixed_size + options_size + 1
    }

    pub fn get_message_type(&self) -> Option<DhcpMessageType> {
        for option in &self.options {
            if let DhcpOption::DhcpMsgType(msg_type) = option {
                return Some(*msg_type);
            }
        }
        None
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 240 {
            return Err("Tamanho da mensagem DHCP inválido");
        }

        let op = bytes[0];
        let htype = bytes[1];
        let hlen = bytes[2];
        let hops = bytes[3];
        let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let secs = u16::from_be_bytes([bytes[8], bytes[9]]);
        let flags = u16::from_be_bytes([bytes[10], bytes[11]]);
        let ciaddr = bytes[12..16].try_into().expect("Dados da mensagem DHCP inválidos");
        let yiaddr = bytes[16..20].try_into().expect("Dados da mensagem DHCP inválidos");
        let siaddr = bytes[20..24].try_into().expect("Dados da mensagem DHCP inválidos");
        let giaddr = bytes[24..28].try_into().expect("Dados da mensagem DHCP inválidos");
        let chaddr = bytes[28..44].try_into().expect("Dados da mensagem DHCP inválidos");
        let sname = bytes[44..108].try_into().expect("Dados da mensagem DHCP inválidos");
        let file = bytes[108..236].try_into().expect("Dados da mensagem DHCP inválidos");
        let options = if bytes.len() > 240 {
            Self::parse_options(&bytes[240..])?
        } else {
            vec![]
        };

        Ok(DhcpMessage {
            op, htype, hlen, hops, xid, secs, flags,
            ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, options
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![
            self.op,
            self.htype,
            self.hlen,
            self.hops,
        ];

        bytes.extend_from_slice(&self.xid.to_be_bytes());
        bytes.extend_from_slice(&self.secs.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.ciaddr);
        bytes.extend_from_slice(&self.yiaddr);
        bytes.extend_from_slice(&self.siaddr);
        bytes.extend_from_slice(&self.giaddr);
        bytes.extend_from_slice(&self.chaddr);
        bytes.extend_from_slice(&self.sname);
        bytes.extend_from_slice(&self.file);
        let magic_cookie = [0x63, 0x82, 0x53, 0x63];
        bytes.extend_from_slice(&magic_cookie);

        for option in &self.options {
            if let Some(serialized_option) = option.serialize() {
                bytes.push(serialized_option.0);
                bytes.push(serialized_option.1);
                bytes.extend_from_slice(&serialized_option.2);
            }
        }

        bytes.push(0xFF);
        bytes
    }

    fn parse_options(bytes: &[u8]) -> Result<Vec<DhcpOption>, &'static str> {
        let mut position = 0;
        let mut options = Vec::new();

        while position < bytes.len() {
            let option_code = bytes[position];
            if option_code == 0xFF {
                break;
            }

            let length = bytes[position + 1] as usize;
            if position + 2 + length > bytes.len() {
                return Err("Erro ao desserializar opções DHCP.");
            }

            let data = &bytes[position + 2..position + 2 + length];

            match DhcpOption::deserialize(option_code, length as u8, data) {
                Some(option) => options.push(option),
                None => eprintln!("Opção DHCP não tratada: {}", option_code),
            }

            position += 2 + length;
        }

        Ok(options)
    }
}
