# Rust Blockchain Application

This is a simple blockchain application written in Rust that demonstrates key blockchain concepts such as block creation, mining with proof-of-work, data encryption, digital signatures, and REST API integration.

## Main Features

- **SHA-256 Hashing:**  
  Uses the `sha2` crate to hash block contents, ensuring data integrity.

- **AES-256 Encryption:**  
  Utilizes AES-256 in CBC mode with PKCS7 padding (via the `aes` and `block-modes` crates) to encrypt block data for added security.

- **Proof-of-Work (PoW):**  
  Implements a basic mining algorithm where a block's nonce is iterated until its hash starts with a predefined number of zeros (difficulty).

- **Digital Signatures:**  
  Employs `ed25519-dalek` to sign each block’s hash, ensuring authenticity and preventing tampering.

- **REST API Endpoints:**  
  The Rocket framework exposes several endpoints:
  - **GET /chain:** Returns the full blockchain in JSON.
  - **POST /add_block:** Adds a new block to the blockchain (expects JSON data).
  - **GET /block/<index>:** Retrieves a specific block by index.
  - **GET /public_key:** Returns the public key (in hex format) used for verifying digital signatures.

## Project Structure

- **src/main.rs:**  
  - **Block Struct:** Represents a block containing an index, timestamp, plain and encrypted data, previous hash, nonce, hash, and a digital signature.
  - **Blockchain Struct:** Manages block creation, addition, and chain validation.
  - **Crypto Utilities Module:** Contains functions for AES encryption/decryption.
  - **Signature Utilities Module:** Contains functions for signing and verifying data.
  - **REST API Endpoints:** Implemented with Rocket to interact with the blockchain.

## How to Run the Application

1. **Install Rust:**  
   Download and install Rust via [rustup](https://rustup.rs/).

2. **Clone or Create the Project:**  
   If you already have the project locally (e.g., created with `cargo new rust_blockchain`), open the project folder.

3. **Build and Run the Application:**  
   In the project directory, run:
   ```bash
   cargo run
