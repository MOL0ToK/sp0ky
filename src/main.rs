#[macro_use]
extern crate lazy_static;

use crate::handler::handle_network;

use clap::{App, Arg};
use pnet::datalink;
use pnet::datalink::NetworkInterface;

use crate::store::Store;
use std::sync::Mutex;
use crate::api::run_api;

mod api;
mod classifier;
mod handler;
mod parser;
mod store;

const STORE_CAPACITY: usize = 50000;

lazy_static! {
    static ref STORE: Mutex<Store> = Mutex::new(Store::new(STORE_CAPACITY));
}

fn main() {
    let matches = App::new("sp0ky")
        .version("0.1.0")
        .author("MOL0ToK <v202bb@gmail.com>")
        .arg(
            Arg::with_name("interface")
                .short("i")
                .required(true)
                .env("SP0KY_INTERFACE")
                .help("Sets the interface to use"),
        )
        .get_matches();

    let interface_name = String::from(matches.value_of("interface").unwrap());
    let interface = find_interface_by_name(&interface_name);

    handle_network(&interface, &STORE);

    let _ = run_api(&STORE);
}

fn find_interface_by_name(interface_name: &String) -> NetworkInterface {
    let interfaces = datalink::interfaces();

    return interfaces
        .into_iter()
        .filter(|interface: &NetworkInterface| interface.name == *interface_name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", interface_name));
}
