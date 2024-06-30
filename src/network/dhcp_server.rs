use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use crate::network::config::INTERFACE_NAME;

pub fn run() {
    let interfaces = datalink::interfaces();
    let interface = interfaces.iter().find(|iface| iface.name == INTERFACE_NAME).expect("Interface não encontrada.");

    let (_tx, mut rx) = setup_network(interface);
    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                handle_packet(interface, &packet);
            },
            Err(e) => {
                eprintln!("Erro recebendo pacote: {}", e);
            }
        }
    }
}

fn setup_network(interface: &NetworkInterface) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Erro ao abrir o canal de comunicação."),
    }
}

// Escuta por pacotes UDP na porta 67, para processar como pacotes DHCP
fn handle_packet(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
            if let Some(udp) = UdpPacket::new(header.payload()) {
                if udp.get_destination() == 67 {
                    println!("DHCP packet received!");
                }
            }
        }
    }
}
