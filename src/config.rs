use std::env;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::sync::OnceLock;
static CONFIG: OnceLock<Config> = OnceLock::new();

pub type HashType = u16;
#[derive(Debug)]
pub struct Config {
    pub pred_id: HashType,
    pub pred_ip: Ipv4Addr,
    pub pred_port: u16,

    pub succ_id: HashType,
    pub succ_ip: Ipv4Addr,
    pub succ_port: u16,

    pub bind_id: HashType,
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
}
pub enum Location {
    Here,
    Successor,
    Unknown,
}
impl Config {
    pub fn get_succ(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.succ_ip, self.succ_port)
    }
    pub fn get_bind(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.bind_ip, self.bind_port)
    }

    pub fn get_pred(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.bind_ip, self.bind_port)
    }
    pub fn is_in_self(&self, hash_value: HashType) -> bool {
        self.pred_id < hash_value && hash_value <= self.bind_id
            || self.bind_id < self.pred_id && hash_value <= self.bind_id
            || self.bind_id < self.pred_id && self.pred_id < hash_value
    }

    pub fn is_in_successor(&self, hash_value: HashType) -> bool {
        self.bind_id < hash_value && hash_value <= self.succ_id
            || self.succ_id < self.bind_id && hash_value <= self.succ_id
            || self.succ_id < self.bind_id && self.bind_id < hash_value
    }
    pub fn where_is_hash(&self, hash_value: HashType) -> Location {
        use Location::*;
        if self.is_in_self(hash_value) {
            Here
        } else if self.is_in_successor(hash_value) {
            Successor
        } else {
            Unknown
        }
    }
}
pub fn get_config() -> &'static Config {
    CONFIG.get().unwrap()
}
pub fn setup_global_config() {
    let pred_id = env::var("PRED_ID")
        .unwrap_or("0".to_string())
        .parse::<HashType>()
        .expect("Invalid Predecessor ID");
    let pred_ip = env::var("PRED_IP")
        .unwrap_or("127.0.0.1".to_string())
        .parse::<Ipv4Addr>()
        .expect("Invalid Predecessor IP");
    let pred_port = env::var("PRED_PORT")
        .unwrap_or("5001".to_string())
        .parse::<u16>()
        .expect("Invalid Predecessor Port");
    let succ_id = env::var("SUCC_ID")
        .unwrap_or("20000".to_string())
        .parse::<HashType>()
        .expect("Invalid Successor ID");
    let succ_ip = env::var("SUCC_IP")
        .unwrap_or("127.0.0.1".to_string())
        .parse::<Ipv4Addr>()
        .expect("Invalid Successor IP");
    let succ_port = env::var("SUCC_PORT")
        .unwrap_or("5003".to_string())
        .parse::<u16>()
        .expect("Invalid Successor Port");

    let mut args = env::args().skip(1);
    let bind_ip = args
        .next()
        .expect("Missing Bind Address")
        .parse::<Ipv4Addr>()
        .expect("Invalid Bind Address");
    let bind_port = args
        .next()
        .expect("Missing Bind Port")
        .parse::<u16>()
        .expect("Invalid Bind Port");
    let bind_id = args
        .next()
        .unwrap_or("10000".to_string())
        .parse::<HashType>()
        .expect("Invalid ID");
    CONFIG
        .set(Config {
            bind_id,
            bind_ip,
            bind_port,

            succ_id,
            succ_ip,
            succ_port,

            pred_id,
            pred_ip,
            pred_port,
        })
        .expect("Config can only be set once");
}
