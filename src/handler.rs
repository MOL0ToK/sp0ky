use std::thread;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use crate::parser::{
    parse_ipv4_packet, parse_ipv6_packet, parse_tcp_packet, IpPacketData, TcpPacketData,
};

use crate::classifier::classify_packets;
use crate::store::Store;

use std::sync::Mutex;

pub fn handle_network(interface: &NetworkInterface, store: &'static Mutex<Store>) {
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    thread::spawn(move || loop {
        match rx.next() {
            Ok(packet) => handle_ethernet_packet(&EthernetPacket::new(packet).unwrap(), store),
            Err(e) => panic!("Unable to receive packet: {}", e),
        }
    });
}

pub fn handle_ethernet_packet(packet: &EthernetPacket, store: &'static Mutex<Store>) {
    let ip_packet_data: Option<IpPacketData> = match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let header = Ipv4Packet::new(packet.payload());
            if let Some(header) = header {
                Some(parse_ipv4_packet(&header))
            } else {
                None
            }
        }
        EtherTypes::Ipv6 => {
            let header = Ipv6Packet::new(packet.payload());
            if let Some(header) = header {
                Some(parse_ipv6_packet(&header))
            } else {
                None
            }
        }
        _ => None,
    };

    let tcp_packet_data: Option<TcpPacketData> = match &ip_packet_data {
        Some(ip_packet_data) => match ip_packet_data.next_protocol {
            IpNextHeaderProtocols::Tcp => {
                let tcp = TcpPacket::new(&ip_packet_data.payload);
                if let Some(tcp) = tcp {
                    Some(parse_tcp_packet(&tcp))
                } else {
                    None
                }
            }
            _ => None,
        },
        None => None,
    };

    if ip_packet_data.is_some() && tcp_packet_data.is_some() {
        classify_packets(&ip_packet_data.unwrap(), &tcp_packet_data.unwrap(), store)
    }
}
