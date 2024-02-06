#![feature(new_uninit)]
#![feature(read_buf)]
#![feature(core_io_borrowed_buf)]
#![feature(never_type)]
use anyhow::Context;
use byteorder::{BigEndian, ByteOrder};
use config::HashType;
use config::Location::{Here, Successor, Unknown};
use dht_project::{
    config, HashTable,
    MessageType::{Lookup, Reply},
    RedirectCache, UDPMessage,
};
use sha2::Digest;
use sha2::Sha256;
use std::io::{BorrowedBuf, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::RwLock;
use std::thread::{self, JoinHandle};
fn main() -> anyhow::Result<!> {
    config::set();
    let config = config::get();
    let cache = RedirectCache::new(10);
    let cache = Arc::new(RwLock::new(cache));
    let udp_socket = UdpSocket::bind((config.bind_ip, config.bind_port))?;

    // Spawn thread with handles to socket and cache
    spawn_udp_listener(
        config.bind_ip,
        config.bind_port,
        config.bind_id,
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
                        let (buf, target) = match config.where_is_hash(recv_message.hash) {
                            Here => (
                                UDPMessage::reply_from_this_node().as_bytes(),
                                recv_message.as_location(),
                            ),
                            Successor => (
                                UDPMessage::reply_from_succ_node().as_bytes(),
                                recv_message.as_location(),
                            ),
                            Unknown => (buf, config.get_succ()),
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
        let config = config::get();
        let listener = TcpListener::bind((bind_address, bind_port))?;
        let table = HashTable::new(id, config.pred_id);
        let table = Arc::new(RwLock::new(table));
        for stream in listener.incoming().map(Result::unwrap) {
            let t_table = table.clone();
            let t_t_cache = cache.clone();
            let socket = udp_socket.try_clone()?;
            thread::spawn(move || handle_connection(&stream, t_table, &socket, t_t_cache));
        }

        unreachable!()
    });
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
        .map_or(Ok(0), |line| {
            line.split(':')
                .nth(1)
                .context("Invalid Content-Length Format")?
                .trim()
                .parse()
                .context("Invalid Content-Length Format")
        });

    Ok(HttpHeader {
        method: method.to_string(),
        path: path.to_string(),
        content_length: content_length?,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::similar_names)]
fn handle_connection(
    stream: &TcpStream,
    hash_table: Arc<RwLock<HashTable>>,
    socket: &UdpSocket,
    t_cache: Arc<RwLock<RedirectCache>>,
) -> anyhow::Result<()> {
    let local_addr = stream.local_addr()?;
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(stream);
    loop {
        let header = read_header(&mut reader)?;

        let hash_value = BigEndian::read_u16(&Sha256::digest(&header.path));
        let config = config::get();
        match config.where_is_hash(hash_value) {
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
                writer.write_all(see_other(config.get_succ(), &header.path).as_bytes())?;
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
                        node_id: config.bind_id,
                        node_ip: match local_addr.ip() {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => panic!("IPv6 not supported"),
                        },
                        node_port: local_addr.port(),
                    };
                    let buf = message.as_bytes();
                    #[allow(clippy::unwrap_used)]
                    socket.send_to(&buf, (config.succ_ip, config.succ_port))?;

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
