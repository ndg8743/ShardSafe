//! Zero-Trust P2P Distributed Storage System
//!
//! Tauri application entry point

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use p2p_storage_lib::storage::ChunkStore;

/// Application state shared across commands
pub struct AppState {
    pub chunk_store: Arc<ChunkStore>,
    pub passphrase: Arc<Mutex<Option<String>>>,
}

/// Get node status
#[tauri::command]
async fn get_status(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let chunk_count = state.chunk_store.chunk_count().map_err(|e| e.to_string())?;

    let storage_bytes = state.chunk_store.total_size().map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "stored_chunks": chunk_count,
        "storage_used_mb": storage_bytes as f64 / (1024.0 * 1024.0),
        "connected": false,
        "peer_count": 0
    }))
}

/// Set passphrase for encryption
#[tauri::command]
async fn set_passphrase(passphrase: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.passphrase.lock().await;
    *guard = Some(passphrase);
    Ok(())
}

/// Check if passphrase is set
#[tauri::command]
async fn has_passphrase(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let guard = state.passphrase.lock().await;
    Ok(guard.is_some())
}

/// Upload a file to the network
#[tauri::command]
async fn upload_file(
    file_path: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use p2p_storage_lib::crypto::{ChunkId, MasterKey};
    use p2p_storage_lib::files::{chunk_data, encode, ErasureConfig, FileManifest, DEFAULT_CHUNK_SIZE};

    // Get passphrase
    let passphrase = {
        let guard = state.passphrase.lock().await;
        guard.clone().ok_or("Passphrase not set")?
    };

    // Read file
    let file_data = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    let filename = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Compute content hash
    let content_hash = *blake3::hash(&file_data).as_bytes();

    // Generate salt and derive master key
    let salt = MasterKey::generate_salt();
    let master_key = MasterKey::derive_from_passphrase(&passphrase, &salt)
        .map_err(|e| format!("Key derivation failed: {:?}", e))?;

    // Create manifest
    let erasure_config = ErasureConfig::default();
    let mut manifest = FileManifest::new(
        filename.clone(),
        file_data.len() as u64,
        salt,
        DEFAULT_CHUNK_SIZE,
        erasure_config,
        content_hash,
    );

    // Chunk the file
    let chunks = chunk_data(&file_data, DEFAULT_CHUNK_SIZE);

    // Process each chunk
    for chunk in &chunks {
        // Derive chunk key
        let chunk_key = master_key.derive_chunk_key(&manifest.file_id, chunk.index);

        // Encrypt chunk
        let encrypted = p2p_storage_lib::crypto::encrypt(&chunk_key, &chunk.data)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        // Erasure encode
        let shards = encode(&encrypted, erasure_config)
            .map_err(|e| format!("Erasure encoding failed: {:?}", e))?;

        // Store shards locally
        let mut shard_locations = Vec::new();
        for (shard_idx, shard_data) in shards.iter().enumerate() {
            let shard_id = ChunkId::from_data(shard_data);

            // Store in local chunk store
            state
                .chunk_store
                .store(&shard_id, shard_data)
                .map_err(|e| format!("Storage failed: {:?}", e))?;

            shard_locations.push(p2p_storage_lib::files::ShardLocation {
                shard_index: shard_idx,
                shard_id,
                peer_ids: vec!["local".to_string()],
            });
        }

        // Add chunk info to manifest
        manifest.add_chunk(p2p_storage_lib::files::ChunkInfo {
            index: chunk.index,
            chunk_id: ChunkId::from_data(&encrypted),
            encrypted_size: encrypted.len(),
            shard_locations,
        });
    }

    // Return result
    Ok(serde_json::json!({
        "file_id": hex::encode(manifest.file_id),
        "filename": manifest.filename,
        "chunks_uploaded": manifest.chunk_count(),
        "original_size": manifest.original_size,
        "success": true
    }))
}

/// List stored files (manifests)
#[tauri::command]
async fn list_files(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let chunk_count = state.chunk_store.chunk_count().map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "files": [],
        "total_chunks": chunk_count
    }))
}

fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("Starting Zero-Trust P2P Storage");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Initialize storage
            let data_dir = dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("p2p-storage");

            std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");

            let chunk_store = Arc::new(
                ChunkStore::open(data_dir.join("chunks"), 10).expect("Failed to open chunk store"),
            );

            tracing::info!("Chunk store opened at {:?}", data_dir);

            // Manage state
            app.manage(AppState {
                chunk_store,
                passphrase: Arc::new(Mutex::new(None)),
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_passphrase,
            has_passphrase,
            upload_file,
            list_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
