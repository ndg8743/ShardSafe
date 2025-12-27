//! P2P Networking Layer
//!
//! Uses libp2p for peer-to-peer communication with:
//! - Kademlia DHT for peer discovery and chunk location
//! - Request-Response protocol for chunk transfer
//! - Noise for encryption, Yamux for multiplexing

pub mod behaviour;
pub mod node;
pub mod protocol;

pub use behaviour::P2PBehaviour;
pub use node::{P2PNode, NodeConfig, NodeEvent};
pub use protocol::{ChunkRequest, ChunkResponse};
