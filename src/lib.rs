pub mod config;
use crate::MessageType::*;
use config::get_config;
use config::HashType;
use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddrV4},
    ops::{Range, RangeInclusive},
    sync::Arc,
};
pub struct HashTable {
    table: Box<[Option<Arc<[u8]>>]>,
    offset: HashType,
}

pub struct RedirectCache {
    queue: VecDeque<(RangeInclusive<HashType>, SocketAddrV4)>,
    max_size: usize,
}

impl RedirectCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_size,
        }
    }

    pub fn push(&mut self, hash_range: Range<HashType>, addr: SocketAddrV4) {
        if self.queue.len() >= self.max_size {
            self.queue.pop_front();
        }
        self.queue
            .push_back((hash_range.start + 1..=hash_range.end, addr));
    }

    pub fn get(&self, hash_value: HashType) -> Option<SocketAddrV4> {
        self.queue.iter().find_map(|(range, addr)| {
            (if range.start() < range.end() {
                range.contains(&hash_value)
            } else {
                range.start() < &hash_value || hash_value <= *range.end()
            })
            .then_some(*addr)
        })
    }
}

impl HashTable {
    pub fn new(id: HashType, pred_id: HashType) -> Self {
        let size = id.wrapping_sub(pred_id);
        Self {
            table: vec![None; size as usize].into_boxed_slice(),
            offset: pred_id,
        }
    }

    pub fn get(&self, index: HashType) -> Option<Arc<[u8]>> {
        self.table[index.wrapping_sub(self.offset) as usize]
            .as_ref()
            .cloned()
    }

    pub fn delete(&mut self, index: HashType) -> Option<Arc<[u8]>> {
        self.table[index.wrapping_sub(self.offset) as usize].take()
    }

    pub fn get_mut(&mut self, index: HashType) -> &mut Option<Arc<[u8]>> {
        &mut self.table[index.wrapping_sub(self.offset) as usize]
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum MessageType {
    Lookup = 0,
    Reply = 1,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0 => Lookup,
            1 => Reply,
            _ => panic!("Invalid MessageType"),
        }
    }
}

#[derive(Debug)]
pub struct UDPMessage {
    pub message_type: MessageType,
    pub hash: HashType,
    pub node_id: HashType,
    pub node_ip: Ipv4Addr,
    pub node_port: u16,
}

impl UDPMessage {
    pub fn as_bytes(&self) -> [u8; 11] {
        let mut buf = [0u8; 11];
        buf[0] = self.message_type as u8;
        [buf[1], buf[2]] = self.hash.to_be_bytes();
        [buf[3], buf[4]] = self.node_id.to_be_bytes();
        [buf[5], buf[6], buf[7], buf[8]] = self.node_ip.octets();
        [buf[9], buf[10]] = self.node_port.to_be_bytes();

        buf
    }

    pub fn as_location(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.node_ip, self.node_port)
    }

    pub fn reply_from_this_node() -> Self {
        let config = get_config();
        Self {
            message_type: Reply,
            hash: config.pred_id,
            node_id: config.bind_id,
            node_ip: config.bind_ip,
            node_port: config.bind_port,
        }
    }

    pub fn reply_from_succ_node() -> Self {
        let config = get_config();
        Self {
            message_type: Reply,
            hash: config.bind_id,
            node_id: config.succ_id,
            node_ip: config.succ_ip,
            node_port: config.succ_port,
        }
    }
}

impl From<[u8; 11]> for UDPMessage {
    fn from(value: [u8; 11]) -> Self {
        UDPMessage {
            message_type: MessageType::from(value[0]),
            hash: HashType::from_be_bytes([value[1], value[2]]),
            node_id: HashType::from_be_bytes([value[3], value[4]]),
            node_ip: Ipv4Addr::from([value[5], value[6], value[7], value[8]]),
            node_port: u16::from_be_bytes([value[9], value[10]]),
        }
    }
}
