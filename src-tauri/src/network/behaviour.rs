//! Combined network behaviour for P2P storage

use libp2p::{
    identify, kad, ping,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    StreamProtocol,
};
use std::time::Duration;

use super::protocol::{ChunkCodec, ChunkRequest, ChunkResponse, CHUNK_PROTOCOL};

/// Combined network behaviour
#[derive(NetworkBehaviour)]
pub struct P2PBehaviour {
    /// Kademlia DHT for peer discovery and content routing
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Request-response for chunk transfers
    pub chunk_transfer: request_response::Behaviour<ChunkCodec>,
    /// Identify protocol for peer info exchange
    pub identify: identify::Behaviour,
    /// Ping for connection keepalive
    pub ping: ping::Behaviour,
}

impl P2PBehaviour {
    /// Create new P2P behaviour
    pub fn new(local_peer_id: libp2p::PeerId, local_public_key: libp2p::identity::PublicKey) -> Self {
        // Kademlia config
        let mut kad_config = kad::Config::new(StreamProtocol::new("/shardsafe/kad/1.0.0"));
        kad_config.set_query_timeout(Duration::from_secs(60));

        let store = kad::store::MemoryStore::new(local_peer_id);
        let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);

        // Chunk transfer protocol
        let chunk_transfer = request_response::Behaviour::new(
            [(CHUNK_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30)),
        );

        // Identify config
        let identify = identify::Behaviour::new(identify::Config::new(
            "/shardsafe/id/1.0.0".to_string(),
            local_public_key,
        ));

        // Ping config
        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30)));

        Self {
            kademlia,
            chunk_transfer,
            identify,
            ping,
        }
    }
}

/// Events from chunk transfer protocol
pub type ChunkTransferEvent = request_response::Event<ChunkRequest, ChunkResponse>;
