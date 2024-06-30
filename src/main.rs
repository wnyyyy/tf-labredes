extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};
use std::env;

fn main() {
    let interface_name = env::args().nth(1).expect("Please specify an interface name");
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .expect("No such network interface.");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating the datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                handle_packet(&interface, &packet);
            },
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn handle_packet(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
            if let Some(udp) = UdpPacket::new(header.payload()) {
                if udp.get_destination() == 67 { // DHCP server port
                    println!("DHCP packet received!");
                    // Handle DHCP logic here
                }
            }
        }
    }
}
