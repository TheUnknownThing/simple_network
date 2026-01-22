use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub Uuid);

impl NodeId {
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4AddrBytes(pub [u8; 4]);

impl Ipv4AddrBytes {
    pub fn from_std(ip: std::net::Ipv4Addr) -> Self {
        Self(ip.octets())
    }

    pub fn to_std(self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.0)
    }
}

pub const WIRE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MsgType {
    Encrypted = 1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WirePacket {
    pub v: u8,
    pub t: MsgType,
    pub src: NodeId,
    pub dst: NodeId,
    pub nonce12: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Inner {
    Register { virtual_ip: Ipv4AddrBytes },
    Data { payload: Vec<u8> },
    Keepalive,
}

pub fn encode_wire(pkt: &WirePacket) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(pkt)
}

pub fn decode_wire(bytes: &[u8]) -> Result<WirePacket, postcard::Error> {
    postcard::from_bytes(bytes)
}

pub fn encode_inner(msg: &Inner) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(msg)
}

pub fn decode_inner(bytes: &[u8]) -> Result<Inner, postcard::Error> {
    postcard::from_bytes(bytes)
}
