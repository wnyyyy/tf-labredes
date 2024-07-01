use std::net::Ipv4Addr;
use pnet::datalink::{DataLinkSender, MacAddr};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{ipv4, MutablePacket, Packet, udp};
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use crate::models::dhcp_message::DhcpMessage;
use crate::models::dhcp_option::{DhcpMessageType, DhcpOption};
use crate::network::config::{BROADCAST_IP, DNS_SERVERS, LEASE_DURATION, SERVER_IP, SERVER_MAC_ADDRESS};
use crate::network::dhcp_lease::DhcpServerState;

pub fn handle_dhcp_packet(sender: &mut dyn DataLinkSender, udp: &UdpPacket, state: &mut DhcpServerState) {
    let result = DhcpMessage::deserialize(udp.payload());
    match result {
        Ok(message) => {
            let message_type = message.get_message_type();
            match message_type {
                Some(DhcpMessageType::Discover) => {
                    let client_mac = MacAddr::new(message.chaddr[0], message.chaddr[1], message.chaddr[2], message.chaddr[3], message.chaddr[4], message.chaddr[5]);
                    println!("DHCP DISCOVER recebido! MAC: {}", client_mac);
                    send_dhcp_offer(sender, message.xid, client_mac, state);
                    println!("DHCP OFFER enviado!");
                },
                Some(DhcpMessageType::Request) => {
                    println!("DHCP REQUEST recebido!");
                    send_dhcp_ack(sender, message.xid, Ipv4Addr::from(message.ciaddr), message.chaddr, state);
                    println!("DHCP ACK enviado!");
                },
                _ => {
                    println!("Pacote DHCP não tratável recebido.");
                }
            }
        },
        Err(e) => {
            eprintln!("Erro ao desserializar pacote DHCP: {}", e);
        }
    }
}

fn send_dhcp_offer(sender: &mut dyn DataLinkSender, transaction_id: u32, client_mac: MacAddr, state: &mut DhcpServerState) {
    let ip = {
        if let Some(lease) = state.get_lease(&client_mac) {
            println!("Cliente MAC: {} já possui um lease: {:?}", client_mac, lease);
        };
        let free_ip = state.find_free_ip().expect("Sem IPs disponíveis.");
        state.add_lease(client_mac, free_ip);
        println!("Lease adicionado para client MAC: {}, IP: {}", client_mac, free_ip);
        free_ip
    };

    // Constrói mensagem DHCP OFFER a ser enviada
    let chaddr = {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&client_mac.octets());
        chaddr
    };
    let options = vec![
        DhcpOption::DhcpMsgType(DhcpMessageType::Offer),
        DhcpOption::SubnetMask([255, 255, 255, 0]),
        DhcpOption::Router(SERVER_IP.octets()),
        DhcpOption::DomainNameServer(vec![DNS_SERVERS[0].octets(), DNS_SERVERS[1].octets()]),
        DhcpOption::IPAddressLeaseTime(LEASE_DURATION as u32),
        DhcpOption::ServerIdentifier(SERVER_IP.octets()),
    ];
    let dhcp_message = DhcpMessage::new(
        2, // Reply
        1, // Ethernet
        6,
        0,
        transaction_id,
        0,
        0x8000, // Broadcast flag
        [0, 0, 0, 0],
        ip.octets(),
        SERVER_IP.octets(),
        [0, 0, 0, 0],
        chaddr,
        [0; 64],
        [0; 128],
        options);

    let dhcp_message_size = dhcp_message.total_size();
    let payload_len = dhcp_message_size + 8 + 20;

    let mut buffer = vec![0u8; payload_len + 14];

    // Frame Ethernet
    let mut ethernet_packet = build_ethernet_frame(&mut buffer, MacAddr::from(SERVER_MAC_ADDRESS), client_mac);

    // Pacote IPV4
    let source = Ipv4Addr::new(0, 0, 0, 0);
    let destination = BROADCAST_IP;
    let mut ipv4_packet = build_ipv4_packet(ethernet_packet.payload_mut(), source, destination, payload_len);

    // Pacote UDP
    let mut udp_packet = build_udp_packet(ipv4_packet.payload_mut(), 67, 68, dhcp_message_size + 8);

    let message_bytes = dhcp_message.serialize();
    udp_packet.set_payload(&message_bytes);
    udp_packet.set_checksum(udp::ipv4_checksum(&udp_packet.to_immutable(), &source, &destination));
    ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

    sender.send_to(ethernet_packet.packet(), None);
}

fn send_dhcp_ack(sender: &mut dyn DataLinkSender, transaction_id: u32, client_address: Ipv4Addr, client_mac_chaddr: [u8; 16], state: &mut DhcpServerState) {
    let client_mac = MacAddr::new(client_mac_chaddr[0], client_mac_chaddr[1], client_mac_chaddr[2], client_mac_chaddr[3], client_mac_chaddr[4], client_mac_chaddr[5]);
    // Verifica se o cliente possui um lease
    let lease = match state.get_lease(&client_mac) {
        Some(lease) => lease,
        None => {
            eprintln!("Sem lease para client MAC: {}", client_mac);
            return;
        }
    };

    // Constrói mensagem DHCP ACK a ser enviada
    let options = vec![
        DhcpOption::DhcpMsgType(DhcpMessageType::Acknowledgement),
        DhcpOption::SubnetMask([255, 255, 255, 0]), 
        DhcpOption::Router(SERVER_IP.octets()),
        DhcpOption::DomainNameServer(vec![DNS_SERVERS[0].octets(), DNS_SERVERS[1].octets()]),
        DhcpOption::IPAddressLeaseTime(LEASE_DURATION as u32),
        DhcpOption::ServerIdentifier(SERVER_IP.octets()),
    ];

    let dhcp_message = DhcpMessage::new(
        2, // Reply
        1, // Ethernet
        6,
        0,
        transaction_id,
        0,
        0x8000, // Broadcast flag
        client_address.octets(),
        lease.ip_address.octets(),
        SERVER_IP.octets(),
        [0, 0, 0, 0],
        client_mac_chaddr,
        [0; 64],
        [0; 128],
        options);

    let dhcp_message_size = dhcp_message.total_size();
    let payload_len = dhcp_message_size + 8 + 20;

    let mut buffer = vec![0u8; payload_len + 14];

    let mut ethernet_packet = build_ethernet_frame(&mut buffer, MacAddr::from(SERVER_MAC_ADDRESS), client_mac);

    let source = Ipv4Addr::new(0, 0, 0, 0);
    let destination = BROADCAST_IP;
    let mut ipv4_packet = build_ipv4_packet(ethernet_packet.payload_mut(), source, destination, payload_len);

    let mut udp_packet = build_udp_packet(ipv4_packet.payload_mut(), 67, 68, dhcp_message_size + 8);

    let message_bytes = dhcp_message.serialize();
    udp_packet.set_payload(&message_bytes);
    udp_packet.set_checksum(udp::ipv4_checksum(&udp_packet.to_immutable(), &source, &destination));
    ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

    sender.send_to(ethernet_packet.packet(), None);
    println!("DHCP ACK enviado para IP: {}", lease.ip_address);
}
fn build_ethernet_frame(buffer: &mut [u8], source_mac: MacAddr, destination_mac: MacAddr) -> MutableEthernetPacket<'_> {
    let mut ethernet_packet = MutableEthernetPacket::new(buffer).unwrap();
    ethernet_packet.set_destination(destination_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_packet
}

fn build_ipv4_packet(ethernet_payload: &mut [u8], source: Ipv4Addr, destination: Ipv4Addr, packet_len: usize) -> MutableIpv4Packet<'_> {
    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_payload).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(packet_len as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_source(source);
    ipv4_packet.set_destination(destination);
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    ipv4_packet
}

fn build_udp_packet(ip_payload: &mut [u8], source_port: u16, destination_port: u16, packet_len: usize) -> MutableUdpPacket<'_> {
    let mut udp_packet = MutableUdpPacket::new(ip_payload).unwrap();
    udp_packet.set_source(source_port);
    udp_packet.set_destination(destination_port);
    udp_packet.set_length(packet_len as u16);
    udp_packet
}
