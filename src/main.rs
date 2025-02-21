// src/main.rs
//
// Rust Blockchain Application with Encryption, Digital Signatures,
// and REST API endpoints.
//
// To run this application, use: cargo run

#[macro_use] extern crate rocket;

use rocket::serde::{json::Json, Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;
use once_cell::sync::Lazy;

// --- SHA-256 Hashing Dependencies from the sha2 crate ---
use sha2::{Sha256, Digest};

// --- AES Encryption Dependencies ---
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex::{encode, decode};

// --- Digital Signature Dependencies ---
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;

// Define type alias for AES-256-CBC using PKCS7 padding.
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Static encryption key and IV for demonstration purposes.
// (For production, use a secure key management solution!)
const AES_KEY: [u8; 32] = [0; 32]; // 32-byte key for AES-256
const AES_IV: [u8; 16] = [0; 16];   // 16-byte IV for AES

// Global keypair for signing blocks using ed25519.
// In production, keys should be stored and managed securely.
static KEYPAIR: Lazy<Keypair> = Lazy::new(|| {
    let mut csprng = OsRng{};
    Keypair::generate(&mut csprng)
});


// --- Module: AES Encryption/Decryption Functions ---
mod crypto_utils {
    use super::*;
    
    /// Encrypts the given plaintext using AES-256-CBC.
    pub fn encrypt_data(data: &str) -> String {
        let cipher = Aes256Cbc::new_from_slices(&AES_KEY, &AES_IV).unwrap();
        let ciphertext = cipher.encrypt_vec(data.as_bytes());
        encode(ciphertext)
    }
    
    /// Decrypts the given hex-encoded ciphertext using AES-256-CBC.
    pub fn decrypt_data(encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let cipher = Aes256Cbc::new_from_slices(&AES_KEY, &AES_IV)?;
        let ciphertext = decode(encrypted_data)?;
        let decrypted_data = cipher.decrypt_vec(&ciphertext)?;
        Ok(String::from_utf8(decrypted_data)?)
    }
}

// --- Module: Digital Signature Functions ---
mod signature_utils {
    use super::*;
    
    /// Signs the given message (in bytes) using the global keypair.
    pub fn sign_message(message: &[u8]) -> String {
        let signature: Signature = KEYPAIR.sign(message);
        encode(signature.to_bytes())
    }
    
    /// Verifies the signature of a message using the provided public key.
    pub fn verify_message(message: &[u8], signature_hex: &str, public_key: &PublicKey) -> bool {
        if let Ok(sig_bytes) = hex::decode(signature_hex) {
            if let Ok(signature) = Signature::from_bytes(&sig_bytes) {
                return public_key.verify(message, &signature).is_ok();
            }
        }
        false
    }
    
    /// Returns the public key in hex format for external verification.
    pub fn get_public_key_hex() -> String {
        encode(KEYPAIR.public.to_bytes())
    }
}

// --- Block Structure ---
// Represents a single block in the blockchain.
#[derive(Serialize, Deserialize, Clone)]
struct Block {
    index: u32,
    timestamp: u64,
    data: String,           // Plain text data (for demonstration)
    encrypted_data: String, // AES-256 encrypted version of the data
    previous_hash: String,
    nonce: u32,
    hash: String,
    signature: String,      // Digital signature of the block's hash
}

impl Block {
    /// Creates a new block instance with the given index, data, and previous hash.
    fn new(index: u32, data: String, previous_hash: String) -> Self {
        let timestamp = Self::current_timestamp();
        // Encrypt the block data.
        let encrypted_data = crypto_utils::encrypt_data(&data);
        Block {
            index,
            timestamp,
            data,
            encrypted_data,
            previous_hash,
            nonce: 0,
            hash: String::new(),
            signature: String::new(),
        }
    }
    
    /// Calculates the SHA-256 hash of the block contents.
    fn calculate_hash(&self) -> String {
        let header = format!("{}{}{}{}{}{}",
                             self.index,
                             self.timestamp,
                             self.encrypted_data,
                             self.previous_hash,
                             self.nonce,
                             self.data);
        // Use the sha2 crate to hash the header.
        let mut hasher = Sha256::new();
        hasher.update(header.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
    
    /// Mines the block by iterating the nonce until the hash meets the required difficulty.
    fn mine_block(&mut self, difficulty: usize) {
        let prefix = "0".repeat(difficulty);
        loop {
            self.hash = self.calculate_hash();
            // Check if the hash starts with the required number of zeros.
            if self.hash.starts_with(&prefix) {
                // Once the condition is met, sign the block hash.
                self.signature = signature_utils::sign_message(self.hash.as_bytes());
                break;
            }
            self.nonce += 1;
        }
        println!("Block {} mined with hash: {}", self.index, self.hash);
    }
    
    /// Utility function to get the current timestamp in seconds.
    fn current_timestamp() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
    
    /// Verifies the digital signature of the block.
    fn verify_signature(&self) -> bool {
        signature_utils::verify_message(self.hash.as_bytes(), &self.signature, &KEYPAIR.public)
    }
}

// --- Blockchain Structure ---
// Manages the chain of blocks and provides functions for adding and validating blocks.
struct Blockchain {
    chain: Vec<Block>,
    difficulty: usize,
}

impl Blockchain {
    /// Creates a new blockchain instance and initializes it with a genesis block.
    fn new() -> Self {
        let mut bc = Blockchain {
            chain: Vec::new(),
            difficulty: 4, // Set the Proof-of-Work difficulty level.
        };
        bc.create_genesis_block();
        bc
    }
    
    /// Creates the genesis (first) block in the blockchain.
    fn create_genesis_block(&mut self) {
        let mut genesis = Block::new(0, "Genesis Block".to_string(), "0".to_string());
        genesis.mine_block(self.difficulty);
        self.chain.push(genesis);
    }
    
    /// Adds a new block to the blockchain with the provided data.
    fn add_block(&mut self, data: String) {
        let last_block = self.chain.last().unwrap();
        let mut new_block = Block::new(last_block.index + 1, data, last_block.hash.clone());
        new_block.mine_block(self.difficulty);
        self.chain.push(new_block);
    }
    
    /// Validates the blockchain by checking each block's hash, previous hash, and digital signature.
    fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];
            if current.hash != current.calculate_hash() {
                return false;
            }
            if current.previous_hash != previous.hash {
                return false;
            }
            if !current.verify_signature() {
                return false;
            }
        }
        true
    }
    
    /// Returns a reference to the entire blockchain.
    fn get_chain(&self) -> &Vec<Block> {
        &self.chain
    }
}

// Create a global blockchain instance wrapped in a Mutex for thread-safe access.
static BLOCKCHAIN: Lazy<Mutex<Blockchain>> = Lazy::new(|| Mutex::new(Blockchain::new()));

// --- REST API Structures and Endpoints ---
// Structure for receiving new block data via API.
#[derive(Deserialize)]
struct NewBlockData {
    data: String,
}

/// GET /chain
/// Returns the entire blockchain in JSON format.
#[get("/chain")]
fn get_chain() -> Json<Vec<Block>> {
    let bc = BLOCKCHAIN.lock().unwrap();
    Json(bc.get_chain().clone())
}

/// POST /add_block
/// Adds a new block with the provided data (expects JSON input).
#[post("/add_block", format = "json", data = "<new_block>")]
fn add_block(new_block: Json<NewBlockData>) -> Json<&'static str> {
    let mut bc = BLOCKCHAIN.lock().unwrap();
    bc.add_block(new_block.data.clone());
    Json("Block added")
}

/// GET /block/<index>
/// Retrieves a specific block by its index.
#[get("/block/<index>")]
fn get_block(index: usize) -> Option<Json<Block>> {
    let bc = BLOCKCHAIN.lock().unwrap();
    bc.get_chain().get(index).map(|block| Json(block.clone()))
}

/// GET /public_key
/// Returns the public key used for signing blocks in hex format.
#[get("/public_key")]
fn public_key() -> Json<String> {
    Json(signature_utils::get_public_key_hex())
}

/// Launch the Rocket server with the defined routes.
#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![get_chain, add_block, get_block, public_key])
}
