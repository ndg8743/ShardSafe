# ShardSafe

Zero-Trust P2P Distributed Storage System with client-side encryption and erasure coding.

## Features

- **Client-Side Encryption**: Files are encrypted before leaving your machine using ChaCha20-Poly1305
- **Key Derivation**: Argon2id with 64MiB memory, 3 iterations for passphrase-based key derivation
- **Content Addressing**: BLAKE3 hashing for chunk identification and integrity verification
- **Erasure Coding**: Split files into shards with redundancy for fault tolerance
- **P2P Distribution**: libp2p-based networking with Kademlia DHT for peer discovery
- **Zero Trust**: Storage nodes only see encrypted shards - they cannot read your data

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ShardSafe Client                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   Crypto    │  │    Files    │  │    Storage      │  │
│  │  - Keys     │  │  - Chunker  │  │  - ChunkStore   │  │
│  │  - Encrypt  │  │  - Erasure  │  │  - Sled DB      │  │
│  │  - Hash     │  │  - Manifest │  │                 │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────┤
│                      P2P Network                         │
│  ┌─────────────────────────────────────────────────────┐│
│  │  libp2p: Kademlia DHT + Request-Response + QUIC     ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

## Building

```bash
# Install dependencies
npm install

# Build the Tauri app
npm run tauri build
```

## Development

```bash
# Run in development mode
npm run tauri dev
```

## Security

- All encryption happens on the client before data leaves your machine
- Passphrase never leaves your device - only derived keys are used
- Each chunk gets a unique key derived from the master key
- Storage nodes cannot decrypt your data
