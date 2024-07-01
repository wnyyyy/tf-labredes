use pnet::datalink::{self, Config};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

pub fn start_gateway_simulation(interface_name: &str) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("(Gateway): Failed to get interface");

    let config = Config::default();
    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("(Gateway): Unhandled channel type"),
        Err(e) => panic!("(Gateway): Failed to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                println!("(Gateway): Received packet with size: {}", packet.len());
                if let Some(ip_packet) = Ipv4Packet::new(packet) {
                    if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            println!("(Gateway): TCP Packet {}:{} -> {}:{}", ip_packet.get_source(), tcp_packet.get_source(), ip_packet.get_destination(), tcp_packet.get_destination());
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("(Gateway): Failed to read packet: {}", e);
                break;
            }
        }
    }
}
