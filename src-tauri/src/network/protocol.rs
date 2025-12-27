//! Chunk transfer protocol definitions

use futures::prelude::*;
use libp2p::{
    request_response::Codec,
    StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::io;

use crate::crypto::ChunkId;

/// Protocol name for chunk transfers
pub const CHUNK_PROTOCOL: StreamProtocol = StreamProtocol::new("/shardsafe/chunk/1.0.0");

/// Request to get or store a chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkRequest {
    /// Request a chunk by ID
    Get { chunk_id: ChunkId },
    /// Store a chunk (chunk_id is computed from data)
    Store { data: Vec<u8> },
    /// Check if peer has a chunk
    Has { chunk_id: ChunkId },
}

/// Response to chunk requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkResponse {
    /// Chunk data
    Chunk { chunk_id: ChunkId, data: Vec<u8> },
    /// Chunk stored successfully
    Stored { chunk_id: ChunkId },
    /// Whether peer has the chunk
    HasResult { chunk_id: ChunkId, has: bool },
    /// Error response
    Error { message: String },
}

/// JSON codec for chunk protocol
#[derive(Debug, Clone, Default)]
pub struct ChunkCodec;

#[async_trait::async_trait]
impl Codec for ChunkCodec {
    type Protocol = StreamProtocol;
    type Request = ChunkRequest;
    type Response = ChunkResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        serde_json::from_slice(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        serde_json::from_slice(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&buf).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&res)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&buf).await?;
        io.close().await?;
        Ok(())
    }
}
