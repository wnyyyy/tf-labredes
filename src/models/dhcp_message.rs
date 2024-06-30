// Estrutura das mensagens DHCP conforme definida em
// https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042653.htm

#[derive(Debug, Clone)]
pub struct DhcpMessage {
    op: u8,          // Message type defined in option field. 1 = REQUEST, 2 = REPLY
    htype: u8,       // Hardware address type and length of a DHCP client.
    hlen: u8,
    hops: u8,        // Number of relay agents a request message traveled.
    xid: u32,        // Transaction ID, a random number chosen by the client to identify an IP address allocation
    secs: u16,       // Filled in by the client, the number of seconds elapsed since the client began address acquisition or renewal process. Currently, this field is reserved and set to 0.
    flags: u16,      // The leftmost bit is defined as the BROADCAST (B) flag. If this flag is set to 0, the DHCP server sent a reply back by unicast;
                     // if this flag is set to 1, the DHCP server sent a reply back by broadcast. The remaining bits of the flags field are reserved for future use.
    ciaddr: [u8; 4], // Client IP address.
    yiaddr: [u8; 4], // 'your' (client) IP address, assigned by the server.
    siaddr: [u8; 4], // Server IP address, from which the client obtained configuration parameters.
    giaddr: [u8; 4], // IP address of the first relay agent a request message traveled.
    chaddr: [u8; 16],// Client hardware address.
    sname: [u8; 64], // Server host name, from which the client obtained configuration parameters.\
    file: [u8; 128], // Bootfile name and path information, defined by the server to the client.
}
