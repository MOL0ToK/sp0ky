use byteorder::{BigEndian, ByteOrder};

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpOptionNumber;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use std::net::IpAddr;

#[derive(Debug)]
pub enum IpPacketType {
    Ipv4,
    Ipv6,
}

#[derive(Debug)]
pub struct IpPacketData {
    pub packet_type: IpPacketType,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub ttl: u8,
    pub flags: Option<u8>,
    pub header_length: u8,
    pub options_length: u8,
    pub next_protocol: IpNextHeaderProtocol,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct TcpPacketData {
    pub source_port: u16,
    pub destination_port: u16,
    pub flags: u16,
    pub header_length: u8,
    pub window_size: u16,
    pub mss: Option<u16>,
    pub mtu: Option<u16>,
    pub wscale: Option<u8>,
    pub sack: bool,
    pub timestamp: Option<u32>,
    pub options: Vec<TcpOptionNumber>,
}

pub fn parse_tcp_packet(packet: &TcpPacket) -> TcpPacketData {
    let mut result = TcpPacketData {
        source_port: packet.get_source(),
        destination_port: packet.get_destination(),
        flags: packet.get_flags(),
        header_length: packet.get_data_offset(),
        window_size: packet.get_window(),
        mss: None,
        mtu: None,
        wscale: None,
        sack: false,
        timestamp: None,
        options: vec![],
    };

    for option in packet.get_options_iter() {
        result.options.push(option.get_number());
        match option.get_number() {
            TcpOptionNumbers::MSS => {
                result.mss = Some(BigEndian::read_u16(option.payload()));
                result.mtu = Some(BigEndian::read_u16(option.payload()) + 40);
            }
            TcpOptionNumbers::WSCALE => {
                result.wscale = Some(option.payload()[0]);
            }
            TcpOptionNumbers::SACK => result.sack = true,
            TcpOptionNumbers::TIMESTAMPS => {
                result.timestamp = Some(BigEndian::read_u32(&option.payload()[0..4]));
            }
            _ => {}
        }
    }

    return result;
}

pub fn parse_ipv4_packet(header: &Ipv4Packet) -> IpPacketData {
    IpPacketData {
        packet_type: IpPacketType::Ipv4,
        source_ip: IpAddr::V4(header.get_source()),
        destination_ip: IpAddr::V4(header.get_destination()),
        ttl: header.get_ttl(),
        flags: Some(header.get_flags()),
        header_length: header.get_header_length(),
        options_length: header.get_options_raw().len() as u8,
        next_protocol: header.get_next_level_protocol(),
        payload: header.payload().to_vec(),
    }
}

pub fn parse_ipv6_packet(header: &Ipv6Packet) -> IpPacketData {
    IpPacketData {
        packet_type: IpPacketType::Ipv6,
        source_ip: IpAddr::V6(header.get_source()),
        destination_ip: IpAddr::V6(header.get_destination()),
        ttl: header.get_hop_limit(),
        flags: None,
        header_length: 40,
        options_length: 0,
        next_protocol: header.get_next_header(),
        payload: header.payload().to_vec(),
    }
}
