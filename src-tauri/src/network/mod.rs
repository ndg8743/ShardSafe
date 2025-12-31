//! P2P Networking Layer
//!
//! Uses libp2p for peer-to-peer communication with:
//! - Kademlia DHT for peer discovery and chunk location
//! - Request-Response protocol for chunk transfer
//! - Noise for encryption, Yamux for multiplexing
//! - Authority-based node selection and consensus

pub mod authority_node;
pub mod behaviour;
pub mod node;
pub mod protocol;

pub use behaviour::P2PBehaviour;
pub use node::{P2PNode, NodeConfig, NodeEvent};
pub use protocol::{ChunkRequest, ChunkResponse};
pub use authority_node::{AuthorityNode, AuthorityNodeConfig, AuthorityEvent, AuthorityError};
