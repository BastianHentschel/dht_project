#![feature(new_uninit)]
#![feature(read_buf)]
#![feature(core_io_borrowed_buf)]
#![feature(never_type)]

use std::io::{BorrowedBuf, BufRead, BufReader, BufWriter, Read, Write};

use crate::Location::{Here, Successor, Unknown};
use crate::MessageType::{Lookup, Reply};
use anyhow::Context;
use byteorder::{BigEndian, ByteOrder};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::ops::{Range, RangeInclusive};
use std::sync::{Arc, OnceLock, RwLock};
use std::thread::JoinHandle;
use std::{env, thread};

type HashType = u16;

struct HashTable {
    table: Box<[Option<Arc<[u8]>>]>,
    offset: HashType,
}

struct RedirectCache {
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

static PRED_ID: OnceLock<HashType> = OnceLock::new();
static PRED_IP: OnceLock<Ipv4Addr> = OnceLock::new();
static PRED_PORT: OnceLock<u16> = OnceLock::new();
static SUCC_ID: OnceLock<HashType> = OnceLock::new();
static SUCC_IP: OnceLock<Ipv4Addr> = OnceLock::new();
static SUCC_PORT: OnceLock<u16> = OnceLock::new();
static ID: OnceLock<HashType> = OnceLock::new();
static BIND_ADDRESS: OnceLock<Ipv4Addr> = OnceLock::new();
static BIND_PORT: OnceLock<u16> = OnceLock::new();

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
    fn as_bytes(&self) -> [u8; 11] {
        let mut buf = [0u8; 11];
        buf[0] = self.message_type as u8;
        [buf[1], buf[2]] = self.hash.to_be_bytes();
        [buf[3], buf[4]] = self.node_id.to_be_bytes();
        [buf[5], buf[6], buf[7], buf[8]] = self.node_ip.octets();
        [buf[9], buf[10]] = self.node_port.to_be_bytes();

        buf
    }

    fn as_location(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.node_ip, self.node_port)
    }

    fn reply_from_this_node() -> Self {
        Self {
            message_type: Reply,
            hash: *PRED_ID.get().unwrap(),
            node_id: *ID.get().unwrap(),
            node_ip: *BIND_ADDRESS.get().unwrap(),
            node_port: *BIND_PORT.get().unwrap(),
        }
    }

    fn reply_from_succ_node() -> Self {
        Self {
            message_type: Reply,
            hash: *ID.get().unwrap(),
            node_id: *SUCC_ID.get().unwrap(),
            node_ip: *SUCC_IP.get().unwrap(),
            node_port: *SUCC_PORT.get().unwrap(),
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

fn main() -> anyhow::Result<!> {
    setup_global_config();
    let mut args = env::args().skip(1);
    let bind_address = args
        .next()
        .expect("Missing Bind Address")
        .parse::<Ipv4Addr>()
        .expect("Invalid Bind Address");
    BIND_ADDRESS.set(bind_address).unwrap();
    let bind_port = args
        .next()
        .expect("Missing Bind Port")
        .parse::<u16>()
        .expect("Invalid Bind Port");
    BIND_PORT.set(bind_port).unwrap();
    let id = args
        .next()
        .unwrap_or("10000".to_string())
        .parse::<HashType>()
        .expect("Invalid ID");

    ID.set(id).unwrap();
    let cache = RedirectCache::new(10);
    let cache = Arc::new(RwLock::new(cache));
    let udp_socket = UdpSocket::bind((bind_address, bind_port))?;

    // Spawn thread with handles to socket and cache
    spawn_udp_listener(
        bind_address,
        bind_port,
        id,
        udp_socket.try_clone()?,
        cache.clone(),
    );

    loop {
        let mut buf = [0; 11];
        if let Ok(size) = udp_socket.recv(&mut buf) {
            if size == buf.len() {
                let recv_message = UDPMessage::from(buf);
                match recv_message.message_type {
                    Lookup => {
                        let (buf, target) = match where_is_hash(recv_message.hash) {
                            Here => (
                                UDPMessage::reply_from_this_node().as_bytes(),
                                recv_message.as_location(),
                            ),
                            Successor => (
                                UDPMessage::reply_from_succ_node().as_bytes(),
                                recv_message.as_location(),
                            ),
                            Unknown => (buf, get_succ()),
                        };
                        udp_socket.send_to(&buf, target)?;
                    }
                    Reply => {
                        cache.write().expect("Poisoned Cache Lock").push(
                            recv_message.hash..recv_message.node_id,
                            recv_message.as_location(),
                        );
                    }
                }
            }
        }
    }
}

fn spawn_udp_listener(
    bind_address: Ipv4Addr,
    bind_port: u16,
    id: HashType,
    udp_socket: UdpSocket,
    cache: Arc<RwLock<RedirectCache>>,
) {
    let _: JoinHandle<anyhow::Result<!>> = thread::spawn(move || {
        let listener = TcpListener::bind((bind_address, bind_port))?;
        #[allow(clippy::unwrap_used)]
        let table = HashTable::new(id, *PRED_ID.get().unwrap());
        let table = Arc::new(RwLock::new(table));
        for stream in listener.incoming().map(Result::unwrap) {
            let t_table = table.clone();
            let t_t_cache = cache.clone();
            let socket = udp_socket.try_clone()?;
            thread::spawn(move || handle_connection(stream, t_table, socket, t_t_cache));
        }

        unreachable!()
    });
}

fn setup_global_config() {
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
}

struct HttpHeader {
    method: String,
    path: String,
    content_length: usize,
}
fn read_header<R: BufRead>(mut reader: R) -> anyhow::Result<HttpHeader> {
    let request: Vec<_> = reader
        .by_ref()
        .lines()
        .map(Result::unwrap)
        .take_while(|line| !line.is_empty())
        .collect();

    let string = request.first().context("missing header")?;
    let mut iter = string.split(' ');
    let method = iter.next().context("missing method")?;
    let path = iter.next().context("missing path")?;

    let content_length = request
        .iter()
        .find(|line| line.starts_with("Content-Length:"))
        .map(|line| {
            line.split(':')
                .nth(1)
                .context("Invalid Content-Length Format")?
                .trim()
                .parse()
                .context("Invalid Content-Length Format")
        })
        .unwrap_or(Ok(0));

    Ok(HttpHeader {
        method: method.to_string(),
        path: path.to_string(),
        content_length: content_length?,
    })
}
fn handle_connection(
    stream: TcpStream,
    hash_table: Arc<RwLock<HashTable>>,
    socket: UdpSocket,
    t_cache: Arc<RwLock<RedirectCache>>,
) -> anyhow::Result<()> {
    let local_addr = stream.local_addr()?;
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    loop {
        let header = read_header(&mut reader)?;

        let hash_value = BigEndian::read_u16(&Sha256::digest(&header.path));
        match where_is_hash(hash_value) {
            // This Node is responsible
            Here => match header.method.as_str() {
                "GET" => {
                    handle_get(&mut writer, &hash_table, hash_value)?;
                }
                "PUT" => {
                    handle_put(
                        &mut writer,
                        &mut reader,
                        &hash_table,
                        hash_value,
                        header.content_length,
                    )?;
                }
                "DELETE" => {
                    handle_delete(&hash_table, &mut writer, hash_value)?;
                }
                _ => panic!("invalid HTTP Method"),
            },
            Successor => {
                writer.write_all(see_other(get_succ(), &header.path).as_bytes())?;
            }
            Unknown => {
                if let Some(location) = t_cache
                    .read()
                    .expect("Poisoned HashTable Lock")
                    .get(hash_value)
                {
                    writer.write_all(see_other(location, &header.path).as_bytes())?;
                } else {
                    let message = UDPMessage {
                        message_type: Lookup,
                        hash: hash_value,
                        #[allow(clippy::unwrap_used)]
                        node_id: *ID.get().unwrap(),
                        node_ip: match local_addr.ip() {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => panic!("IPv6 not supported"),
                        },
                        node_port: local_addr.port(),
                    };
                    let buf = message.as_bytes();
                    #[allow(clippy::unwrap_used)]
                    socket.send_to(&buf, (*SUCC_IP.get().unwrap(), *SUCC_PORT.get().unwrap()))?;

                    writer.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\n\r\n")?;
                }
            }
        };
        writer.flush()?;
    }
}

fn handle_delete(
    hash_table: &Arc<RwLock<HashTable>>,
    writer: &mut BufWriter<&TcpStream>,
    hash_value: u16,
) -> anyhow::Result<()> {
    let header: &[u8] = match hash_table
        .write()
        .expect("Poisoned HashTable Lock")
        .delete(hash_value)
    {
        Some(_) => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        None => b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    };
    writer.write_all(header)?;

    Ok(())
}

fn get_succ() -> SocketAddrV4 {
    SocketAddrV4::new(*SUCC_IP.get().unwrap(), *SUCC_PORT.get().unwrap())
}

fn see_other(location: SocketAddrV4, path: &str) -> String {
    format!(
        "HTTP/1.1 303 See Other\r\nLocation: http://{ip}:{port}{path}\r\nContent-Length: 0\r\n\r\n",
        ip = location.ip(),
        port = location.port()
    )
}

fn handle_put(
    writer: &mut BufWriter<&TcpStream>,
    reader: &mut BufReader<&TcpStream>,
    table: &Arc<RwLock<HashTable>>,
    hash_value: HashType,
    content_length: usize,
) -> anyhow::Result<()> {
    let mut content = Arc::new_uninit_slice(content_length);
    #[allow(clippy::unwrap_used)]
    let mut borrow = BorrowedBuf::from(Arc::get_mut(&mut content).unwrap());
    reader
        .read_buf_exact(borrow.unfilled())
        .expect("Error reading content");
    let content = unsafe { content.assume_init() };
    *table
        .write()
        .expect("Poisoned HashTable Lock")
        .get_mut(hash_value) = Some(content);

    writer.write_all("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".as_bytes())?;

    Ok(())
}

fn handle_get(
    stream: &mut BufWriter<&TcpStream>,
    table: &Arc<RwLock<HashTable>>,
    hash_value: HashType,
) -> anyhow::Result<()> {
    if let Some(content) = table
        .read()
        .expect("Poisoned HashTable Lock")
        .get(hash_value)
    {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            content.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.write_all(&content)?;
    } else {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes())?;
    }

    Ok(())
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
