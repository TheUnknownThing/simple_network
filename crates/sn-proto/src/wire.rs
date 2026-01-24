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

pub const WIRE_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MsgType {
    /// Client <-> relay control-plane messages.
    ///
    /// These are encrypted with a per-node key derived from the relay PSK.
    Control = 1,
    /// End-to-end encrypted data-plane messages.
    ///
    /// The relay forwards these opaquely without decrypting.
    Data = 2,
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
pub enum Control {
    /// Client -> relay: bind node_id to its virtual IPv4.
    Register { virtual_ip: Ipv4AddrBytes },
    /// Client -> relay: keep NAT mapping alive.
    Keepalive,

    /// Client -> relay: resolve a virtual IPv4 to a node_id.
    Resolve { virtual_ip: Ipv4AddrBytes },
    /// Relay -> client: resolution succeeded.
    ResolveOk { virtual_ip: Ipv4AddrBytes, node_id: NodeId },
    /// Relay -> client: resolution failed.
    ResolveErr { virtual_ip: Ipv4AddrBytes },
}

pub fn encode_wire(pkt: &WirePacket) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(pkt)
}

pub fn decode_wire(bytes: &[u8]) -> Result<WirePacket, postcard::Error> {
    postcard::from_bytes(bytes)
}

pub fn encode_control(msg: &Control) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(msg)
}

pub fn decode_control(bytes: &[u8]) -> Result<Control, postcard::Error> {
    postcard::from_bytes(bytes)
}
