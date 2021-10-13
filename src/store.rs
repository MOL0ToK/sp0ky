use std::collections::HashMap;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub enum OS {
    Windows,
    MacOS,
    Linux,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct ClientData {
    pub os: OS,
    pub signature: String
}

#[derive(Debug)]
pub struct Store {
    addresses: Vec<String>,
    clients: HashMap<String, ClientData>,
    cap: usize,
}

impl Store {
    pub fn new(cap: usize) -> Store {
        Store {
            addresses: Vec::new(),
            clients: HashMap::new(),
            cap,
        }
    }

    pub fn add_new_client(&mut self, address: String, client_data: ClientData) {
        if self.clients.get(&address).is_some() {
            return;
        }

        if self.addresses.len() > self.cap {
            let last_address = self.addresses.remove(0);
            self.clients.remove(&last_address);
        }

        self.clients.insert(address.clone(), client_data);
        self.addresses.push(address.clone());
    }

    pub fn get_client(&self, ip: &str) -> Option<&ClientData> {
        self.clients.get(ip)
    }
}
