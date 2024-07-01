use std::thread::sleep;
use std::time::{Duration, Instant};
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use crate::network::config::{INTERFACE_NAME, LEASE_DURATION};
use crate::network::dhcp::handle_dhcp_packet;
use crate::network::dhcp_lease::DhcpServerState;

pub fn run() {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == INTERFACE_NAME)
        .expect("Interface não encontrada.");

    let (mut tx, mut rx) = setup_network(&interface);

    let mut state = DhcpServerState::new();

    let lease_check_interval = Duration::from_secs(10);
    let mut last_checked = Instant::now();

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                handle_packet(&mut *tx, &packet, &mut state);
            },
            Err(e) => {
                eprintln!("Erro recebendo pacote: {}", e);
            }
        }

        // Verifica periodicamente se há leases expirados
        if last_checked.elapsed() >= lease_check_interval {
            state.expire_leases();
            last_checked = Instant::now();
        }
        // porque rx.next() aparentemente não é blocking
        sleep(Duration::from_millis(10));
    }
}


// Configura raw socket para enviar e receber pacotes
fn setup_network(interface: &NetworkInterface) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Erro ao abrir o canal de comunicação."),
    }
}

// Escuta por pacotes UDP na porta 67, para processar como pacotes DHCP
fn handle_packet(sender: &mut dyn DataLinkSender, ethernet: &EthernetPacket, state: &mut DhcpServerState) {
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
            if let Some(udp) = UdpPacket::new(header.payload()) {
                if udp.get_destination() == 67 {
                    handle_dhcp_packet(sender, &udp, state);
                }
            }
        }
    }
}
