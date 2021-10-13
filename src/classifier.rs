use crate::parser::{IpPacketData, IpPacketType, TcpPacketData};
use crate::store::{ClientData, Store, OS};
use serde::Serialize;
use std::sync::Mutex;

use pnet::packet::tcp::{TcpFlags, TcpOptionNumber, TcpOptionNumbers};

#[derive(Debug, Serialize)]
struct ConsoleMessage {
    address: String,
    os: OS,
    signature: String,
}

impl ConsoleMessage {
    pub fn new(address: &String, client_data: &ClientData) -> ConsoleMessage {
        return ConsoleMessage {
            address: address.clone(),
            os: client_data.os.clone(),
            signature: client_data.signature.clone(),
        };
    }
}

pub fn classify_packets(
    ip_packet_data: &IpPacketData,
    tcp_packet_data: &TcpPacketData,
    store: &'static Mutex<Store>,
) {
    // Classify only SYN packets
    if (tcp_packet_data.flags & TcpFlags::SYN != 0) && (tcp_packet_data.flags & TcpFlags::ACK == 0)
    {
        let address = format!(
            "{}:{}",
            ip_packet_data.source_ip.to_string(),
            tcp_packet_data.source_port.to_string()
        );

        let signature = gen_signature(ip_packet_data, tcp_packet_data);

        let os = detect_os(ip_packet_data, tcp_packet_data);

        let client_data = ClientData { os, signature };

        let console_message = ConsoleMessage::new(&address, &client_data);

        println!("{}", serde_json::to_string(&console_message).unwrap());

        let mut store = store.lock().unwrap();
        store.add_new_client(address, client_data);
    }
}

fn gen_signature(ip_packet_data: &IpPacketData, tcp_packet_data: &TcpPacketData) -> String {
    let mut sig_vec = Vec::new();

    // IP version
    let ip_ver = match ip_packet_data.packet_type {
        IpPacketType::Ipv4 => "4".to_string(),
        IpPacketType::Ipv6 => "6".to_string(),
    };

    let hops = match ip_packet_data.ttl {
        0..=64 => (64 - ip_packet_data.ttl).to_string(),
        65..=128 => (128 - ip_packet_data.ttl).to_string(),
        _ => "?".to_string(),
    };

    let mss = match tcp_packet_data.mss {
        Some(mss) => mss.to_string(),
        None => "?".to_string(),
    };

    let wscale = match tcp_packet_data.wscale {
        Some(wscale) => wscale.to_string(),
        None => "?".to_string(),
    };

    let options = tcp_packet_data
        .options
        .iter()
        .map(|number| convert_tcp_option_number(number))
        .collect::<Vec<String>>()
        .join(",");

    let ip_flags = match ip_packet_data.flags {
        Some(ip_flags) => format!("{:02b}", ip_flags),
        None => "?".to_string(),
    };

    let tcp_flags = format!("{:09b}", tcp_packet_data.flags);

    sig_vec.push(ip_ver);
    sig_vec.push(format!("{}+{}", ip_packet_data.ttl, hops));
    sig_vec.push(ip_packet_data.options_length.to_string());
    sig_vec.push(mss);
    sig_vec.push(tcp_packet_data.window_size.to_string());
    sig_vec.push(wscale);
    sig_vec.push(options);
    sig_vec.push(ip_flags);
    sig_vec.push(tcp_flags);

    return sig_vec.join(":");
}

fn convert_tcp_option_number(tcp_option_number: &TcpOptionNumber) -> String {
    match *tcp_option_number {
        TcpOptionNumbers::NOP => "nop".to_string(),
        TcpOptionNumbers::MSS => "mss".to_string(),
        TcpOptionNumbers::WSCALE => "ws".to_string(),
        TcpOptionNumbers::SACK_PERMITTED => "sok".to_string(),
        TcpOptionNumbers::EOL => "eol".to_string(),
        TcpOptionNumbers::TIMESTAMPS => "ts".to_string(),
        TcpOptionNumbers::SACK => "sack".to_string(),
        _ => "?".to_string(),
    }
}

fn detect_os(ip_packet_data: &IpPacketData, tcp_packet_data: &TcpPacketData) -> OS {
    if ip_packet_data.ttl > 64
        && ip_packet_data.ttl < 128
        && tcp_packet_data.options
            == vec![
                TcpOptionNumbers::MSS,
                TcpOptionNumbers::NOP,
                TcpOptionNumbers::WSCALE,
                TcpOptionNumbers::NOP,
                TcpOptionNumbers::NOP,
                TcpOptionNumbers::SACK_PERMITTED,
            ]
    {
        return OS::Windows;
    }

    if ip_packet_data.ttl <= 64
        && tcp_packet_data.options
            == vec![
                TcpOptionNumbers::MSS,
                TcpOptionNumbers::NOP,
                TcpOptionNumbers::WSCALE,
                TcpOptionNumbers::NOP,
                TcpOptionNumbers::NOP,
                TcpOptionNumbers::TIMESTAMPS,
                TcpOptionNumbers::SACK_PERMITTED,
                TcpOptionNumbers::EOL,
                TcpOptionNumbers::EOL,
            ]
    {
        return OS::MacOS;
    }

    if ip_packet_data.ttl <= 64
        && tcp_packet_data.options
            == vec![
                TcpOptionNumbers::MSS,
                TcpOptionNumbers::SACK_PERMITTED,
                TcpOptionNumbers::TIMESTAMPS,
                TcpOptionNumbers::NOP,
                TcpOptionNumbers::WSCALE,
            ]
    {
        return OS::Linux;
    }

    return OS::Unknown;
}
