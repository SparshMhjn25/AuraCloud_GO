
# AuraCloud: Zero-Knowledge Peer-to-Peer Private Media Backup System

AuraCloud is a single-binary, zero-knowledge, peer-to-peer (P2P) private backup and replication engine written in Go. It eliminates central cloud storage providers, external VPN daemons, and heavy DHT/blockchain overhead by embedding a userspace WireGuard mesh (`tsnet`) directly alongside client-side `AES-256-GCM` authenticated encryption, deterministic `2 MiB` content-addressed chunking, and an atomic `SQLite` (WAL mode) state queue.

---

## 1. Key Architectural Highlights

* **Zero-Dependency Single Binary:** Compiles into a standalone native executable (`auracloud.exe` on Windows `amd64`, `auracloud` on macOS `arm64`/Linux) with an embedded web console (`web/`), requiring no external Tailscale daemon, root privileges, or third-party databases.
* **Untrusted-Peer Zero-Knowledge Model:** Each node initializes an isolated vault using `Argon2id` key derivation and a 16-byte random recovery salt. Master encryption keys never leave the originating node; remote backup peers store and verify encrypted chunks via `SHA-256(ciphertext) == CID` without ever accessing plaintext files or metadata.
* **Embedded Userspace WireGuard Mesh (`tsnet`):** Performs automatic NAT traversal across independent consumer ISPs and residential routers over encrypted WireGuard tunnels.
* **Crash-Safe Atomic Manifest & Resumable Queue:** Uses `SQLite` in Write-Ahead Logging (`WAL`) mode to track file manifests, `2 MiB` chunk mappings, and a 3-worker parallel background replication queue (`pending_chunks`).

---

## 2. System Architecture & Data Pipeline

### End-to-End Ingestion & Replication Flow

```text
+-----------------------------------------------------------------------------------+
|                        SENDER NODE (e.g., Windows 11 amd64)                       |
|                                                                                   |
|  [Web UI / REST API: POST /api/v1/files/upload]                                   |
|         |                                                                         |
|         v                                                                         |
|  1. Chunker (pkg/chunker) ──────► Splits stream into fixed 2 MiB (2,097,152 B)     |
|         |                                                                         |
|         v                                                                         |
|  2. Crypto Engine (pkg/crypto) ─► Argon2id Master Key -> AES-256-GCM + AAD        |
|         |                         Computes SHA-256 Content ID (CID) on ciphertext  |
|         v                                                                         |
|  3. State & Storage (pkg/db, pkg/storage)                                         |
|         ├──► Writes encrypted chunk blobs to .auracloud_data/chunks/<cid>         |
|         └──► Atomically commits file manifest & pending_chunks in SQLite (WAL)    |
|         |                                                                         |
|         v                                                                         |
|  4. Replication Workers (pkg/sync - 3 Concurrent Workers)                         |
|         └──► Dispatches chunks & manifests over embedded Tailscale (tsnet)        |
+-----------------------------------------------------------------------------------+
                                          |
                          Encrypted WireGuard Tunnel (NAT Traversal)
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                       RECEIVER PEER (e.g., macOS Darwin arm64)                    |
|                                                                                   |
|  5. Mesh Endpoints (pkg/api: POST /api/v1/chunks/receive & /api/v1/manifest/sync) |
|         |                                                                         |
|         v                                                                         |
|  6. Zero-Knowledge Integrity Gate                                                 |
|         ├──► Recomputes SHA-256(received_ciphertext) == CID                       |
|         ├──► Persists verified opaque chunks & manifest in local SQLite (WAL)     |
|         └──► Isolated Vault: Receiver has NO access to sender's Argon2id key      |
+-----------------------------------------------------------------------------------+

Cryptographic & Threat Model Design
Key Derivation: Passphrase + 16-byte random hex salt processed via Argon2id to derive a 256-bit vault master key held strictly in volatile memory while unlocked.

Authenticated Encryption: Each 2 MiB chunk is encrypted using AES-256-GCM with unique nonces and Additional Authenticated Data (AAD) binding chunk index and file context to prevent chunk-reordering or substitution attacks.

Content-Addressed Integrity: Every encrypted chunk is indexed by CID = SHA-256(ciphertext), allowing untrusted storage peers to verify bit-level integrity on receipt and deduplicate identical blocks without decryption.


Build & Run Instructions
Prerequisites
Go 1.22+

A Tailscale account (for cross-network tsnet mesh mode; local mode works completely offline)

Build Native Binaries
Bash
# Windows (amd64)
go build -o auracloud.exe .

# macOS (Apple Silicon arm64)
GOOS=darwin GOARCH=arm64 go build -o auracloud .

# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o auracloud-linux .

Launch & Initialize Vault
Run ./auracloud (or .\auracloud.exe on Windows).

Select 5 to start in Tailscale Mesh Mode (or Local Mode for single-node testing) and authenticate the printed Tailscale login URL on first boot.

Open http://127.0.0.1:8080 in your browser, enter a Vault Passphrase (leaving Recovery Salt blank on initial setup), and click Unlock Vault.

Save the generated 16-byte Recovery Salt displayed in the dashboard header alongside your passphrase.

Team & Contributions
Sparsh Mahajan — System Architecture, Core Go Engine, AES-256-GCM & Argon2id Cryptography, tsnet Mesh Networking, Cross-OS Benchmarking

Shreya Singh — SQLite WAL Manifest Schema, File Reconstruction Pipeline, Security Verification

Vanshika Shukla — Embedded Web Console UI, REST API Integration, Technical Documentation
'@ | Set-Content -Path "README.md" -Encoding UTF8

git add .
git commit -m "Add complete system architecture README, .gitignore, Go P2P engine, and 1GB benchmark results"
git branch -M main
git status