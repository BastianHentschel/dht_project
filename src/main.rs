use std::io::{BufRead, BufReader, BufWriter, Read, Write};

use crate::Location::{Here, Successor, Unknown};
use crate::MessageType::{Lookup, Reply};
use byteorder::{BigEndian, ByteOrder};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::ops::{Range, RangeInclusive};
use std::sync::{Arc, OnceLock, RwLock};
use std::{env, thread};

type HashType = u16;

struct HashTable {
    table: Box<[Option<Arc<[u8]>>]>,
    offset: HashType,
}

struct RedirectCache {
    queue: VecDeque<(RangeInclusive<HashType>, (Ipv4Addr, u16))>,
    max_size: usize,
}

impl RedirectCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_size,
        }
    }

    pub fn push(&mut self, hash_range: Range<HashType>, addr: (Ipv4Addr, u16)) {
        if self.queue.len() >= self.max_size {
            self.queue.pop_front();
        }
        self.queue
            .push_back((hash_range.start + 1..=hash_range.end, addr))
    }

    pub fn get(&self, hash_value: HashType) -> Option<(Ipv4Addr, u16)> {
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

static PRED_ID: OnceLock<HashType> = OnceLock::new();
static PRED_IP: OnceLock<Ipv4Addr> = OnceLock::new();
static PRED_PORT: OnceLock<u16> = OnceLock::new();
static SUCC_ID: OnceLock<HashType> = OnceLock::new();
static SUCC_IP: OnceLock<Ipv4Addr> = OnceLock::new();
static SUCC_PORT: OnceLock<u16> = OnceLock::new();
static ID: OnceLock<HashType> = OnceLock::new();

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
enum MessageType {
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
struct UDPMessage {
    message_type: MessageType,
    hash: HashType,
    node_id: HashType,
    node_ip: Ipv4Addr,
    node_port: u16,
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

fn main() {
    let pred_id = env::var("PRED_ID")
        .unwrap_or("0".to_string())
        .parse::<HashType>()
        .expect("Invalid Predecessor ID");
    PRED_ID.set(pred_id).unwrap();
    let pred_ip = env::var("PRED_IP")
        .unwrap_or("127.0.0.1".to_string())
        .parse::<Ipv4Addr>()
        .expect("Invalid Predecessor IP");
    PRED_IP.set(pred_ip).unwrap();
    let pred_port = env::var("PRED_PORT")
        .unwrap_or("5001".to_string())
        .parse::<u16>()
        .expect("Invalid Predecessor Port");
    PRED_PORT.set(pred_port).unwrap();
    let succ_id = env::var("SUCC_ID")
        .unwrap_or("20000".to_string())
        .parse::<HashType>()
        .expect("Invalid Successor ID");
    SUCC_ID.set(succ_id).unwrap();
    let succ_ip = env::var("SUCC_IP")
        .unwrap_or("127.0.0.1".to_string())
        .parse::<Ipv4Addr>()
        .expect("Invalid Successor IP");
    SUCC_IP.set(succ_ip).unwrap();
    let succ_port = env::var("SUCC_PORT")
        .unwrap_or("5003".to_string())
        .parse::<u16>()
        .expect("Invalid Successor Port");
    SUCC_PORT.set(succ_port).unwrap();
    let mut args = env::args().skip(1);
    let bind_address = args
        .next()
        .expect("Missing Bind Address")
        .parse::<Ipv4Addr>()
        .expect("Invalid Bind Address");
    let bind_port = args
        .next()
        .expect("Missing Bind Port")
        .parse::<u16>()
        .expect("Invalid Bind Port");

    let id = args
        .next()
        .unwrap_or("10000".to_string())
        .parse::<HashType>()
        .expect("Invalid ID");
    ID.set(id).unwrap();
    let cache = RedirectCache::new(10);
    let cache = Arc::new(RwLock::new(cache));
    let t_cache = cache.clone();
    let udp_socket = UdpSocket::bind((bind_address, bind_port)).unwrap();
    let t_udp_socket = udp_socket.try_clone().unwrap();
    thread::spawn(move || {
        let listener = TcpListener::bind((bind_address, bind_port)).unwrap();
        let table = HashTable::new(id, pred_id);
        let table = Arc::new(RwLock::new(table));
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            let t_table = table.clone();
            let t_t_cache = t_cache.clone();
            let socket = t_udp_socket.try_clone().unwrap();
            thread::spawn(move || handle_connection(stream, t_table, socket, t_t_cache));
        }
    });

    loop {
        let mut buf = [0; 11];
        if let Ok(size) = udp_socket.recv(&mut buf) {
            if size == buf.len() {
                let recv_message = UDPMessage::from(buf);
                let recv_message = UDPMessage {
                    message_type: recv_message.message_type,
                    hash: recv_message.hash,
                    node_id: recv_message.node_id,
                    node_ip: recv_message.node_ip,
                    node_port: recv_message.node_port,
                };
                match recv_message.message_type {
                    Lookup => match where_is_hash(recv_message.hash) {
                        Here => {
                            let message = UDPMessage {
                                message_type: Reply,
                                hash: *PRED_ID.get().unwrap(),
                                node_id: *ID.get().unwrap(),
                                node_ip: bind_address,
                                node_port: bind_port,
                            };
                            let buf = message.as_bytes();

                            udp_socket
                                .send_to(&buf, (recv_message.node_ip, recv_message.node_port))
                                .unwrap();
                        }
                        Successor => {
                            let message = UDPMessage {
                                message_type: Reply,
                                hash: *ID.get().unwrap(),
                                node_id: *SUCC_ID.get().unwrap(),
                                node_ip: *SUCC_IP.get().unwrap(),
                                node_port: *SUCC_PORT.get().unwrap(),
                            };
                            let buf = message.as_bytes();
                            udp_socket
                                .send_to(&buf, (recv_message.node_ip, recv_message.node_port))
                                .unwrap();
                        }
                        Unknown => {
                            udp_socket
                                .send_to(&buf, (*SUCC_IP.get().unwrap(), *SUCC_PORT.get().unwrap()))
                                .unwrap();
                        }
                    },
                    Reply => {
                        cache.write().unwrap().push(
                            recv_message.hash..recv_message.node_id,
                            (recv_message.node_ip, recv_message.node_port),
                        );
                    }
                }
            }
        }
    }
}

fn handle_connection(
    stream: TcpStream,
    hash_table: Arc<RwLock<HashTable>>,
    socket: UdpSocket,
    t_cache: Arc<RwLock<RedirectCache>>,
) {
    let local_addr = stream.local_addr().unwrap();
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    loop {
        let request: Vec<_> = reader
            .by_ref()
            .lines()
            .map(Result::unwrap)
            .take_while(|line| !line.is_empty())
            .collect();

        let mut iter = if let Some(iter) = request.get(0) {
            iter.split(' ')
        } else {
            break;
        };
        let method = iter.next().unwrap();
        let path = iter.next().unwrap();

        let content_length = request
            .iter()
            .find(|line| line.starts_with("Content-Length:"))
            .map(|line| line.split(':').nth(1).unwrap().trim())
            .map(str::parse::<usize>)
            .map(Result::unwrap)
            .unwrap_or(0);

        let hash = Sha256::digest(path);
        let hash_value = BigEndian::read_u16(&hash);
        use Location::*;
        let response = match where_is_hash(hash_value) {
            // This Node is responsible
            Here => match method {
                "GET" => {
                    handle_get(writer, hash_table, hash_value);
                    return;
                }
                "PUT" => {
                    let mut content = vec![0; content_length];
                    reader
                        .read_exact(&mut content)
                        .expect("Error reading content");
                    handle_put(
                        writer,
                        hash_table,
                        hash_value,
                        Arc::from(content.into_boxed_slice()),
                    );
                    return;
                }
                "DELETE" => {
                    let mut table = hash_table.write().unwrap();
                    if table.delete(hash_value).is_some() {
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string()
                    } else {
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string()
                    }
                }
                _ => panic!("invalid HTTP Method"),
            },
            Successor => {
                format!(
                    "HTTP/1.1 303 See Other\r\nLocation: http://{ip}:{port}{path}\r\nContent-Length: 0\r\n\r\n",
                    ip = SUCC_IP.get().unwrap(),
                    port = SUCC_PORT.get().unwrap()
                )
            }
            Unknown => {
                if let Some(location) = t_cache.read().unwrap().get(hash_value) {
                    format!(
                        "HTTP/1.1 303 See Other\r\nLocation: http://{ip}:{port}{path}\r\nContent-Length: 0\r\n\r\n",
                        ip = location.0,
                        port = location.1)
                } else {
                    let message = UDPMessage {
                        message_type: Lookup,
                        hash: hash_value,
                        node_id: *ID.get().unwrap(),
                        node_ip: {
                            match local_addr.ip() {
                                IpAddr::V4(addr) => addr,
                                _ => panic!("IPv6 not supported"),
                            }
                        },
                        node_port: local_addr.port(),
                    };
                    let buf = message.as_bytes();
                    socket
                        .send_to(&buf, (*SUCC_IP.get().unwrap(), *SUCC_PORT.get().unwrap()))
                        .unwrap();

                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\n\r\n"
                        .to_string()
                }
            }
        };
        writer.write_all(response.as_bytes()).unwrap();
        writer.flush().unwrap();
    }
}

fn handle_put(
    mut stream: BufWriter<&TcpStream>,
    table: Arc<RwLock<HashTable>>,
    hash_value: HashType,
    content: Arc<[u8]>,
) {
    *table.write().unwrap().get_mut(hash_value) = Some(content);
    stream
        .write_all("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".as_bytes())
        .unwrap();
}

fn handle_get(
    mut stream: BufWriter<&TcpStream>,
    table: Arc<RwLock<HashTable>>,
    hash_value: HashType,
) {
    if let Some(content) = table.read().unwrap().get(hash_value) {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            content.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&content).unwrap()
    } else {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap()
    }
}

enum Location {
    Here,
    Successor,
    Unknown,
}

fn where_is_hash(hash_value: HashType) -> Location {
    if is_in_self(hash_value) {
        Here
    } else if is_in_successor(hash_value) {
        Successor
    } else {
        Unknown
    }
}

fn is_in_self(hash_value: HashType) -> bool {
    *PRED_ID.get().unwrap() < hash_value && hash_value <= *ID.get().unwrap()
        || *ID.get().unwrap() < *PRED_ID.get().unwrap() && hash_value <= *ID.get().unwrap()
        || *ID.get().unwrap() < *PRED_ID.get().unwrap() && *PRED_ID.get().unwrap() < hash_value
}

fn is_in_successor(hash_value: HashType) -> bool {
    *ID.get().unwrap() < hash_value && hash_value <= *SUCC_ID.get().unwrap()
        || *SUCC_ID.get().unwrap() < *ID.get().unwrap() && hash_value <= *SUCC_ID.get().unwrap()
        || *SUCC_ID.get().unwrap() < *ID.get().unwrap() && *ID.get().unwrap() < hash_value
}
