# TorChat V2 - Cryptographic Specification

## 1. Overview
This document specifies the cryptographic primitives, protocols, and security invariants for TorChat V2. 
Verification is performed against official IETF Known Answer Tests (KAT).

## 2. Primitives

| Purpose | Algorithm | Specification | Verification |
| :--- | :--- | :--- | :--- |
| Key Agreement (Handshake) | X25519 (ECDH) | RFC 7748 | RFC 7748 Sec 6.1 (KAT) |
| Signatures (Identity) | Ed25519 | RFC 8032 | RFC 8032 Case 1 (KAT) |
| Hash Function | SHA-256 / SHA-512 | FIPS 180-4 | FIPS/RFC (KAT) |
| Key Derivation (KDF) | HKDF-SHA-256 | RFC 5869 | RFC 5869 Case 1 (KAT) |
| Messaging AEAD | ChaCha20-Poly1305 | RFC 8439 | RFC 8439 Sec 2.8.2 (KAT) |
| Vault AEAD | AES-256-GCM | NIST SP 800-38D | Tink Implementation |

## 3. Security Invariants

### 3.1. Key Lifecycle
- **Immutability:** All key materials are wrapped in classes that clone input byte arrays.
- **Destruction:** `destroy()` method uses `Arrays.fill(0)` to overwrite key material in memory and nullifies references.
- **Access Control:** Module isolation via Gradle ensures Bouncy Castle and Tink classes are not exposed to high-level modules.

### 3.2. Verification Gates
- **All-Zero Shared Secret:** X25519 shared secrets are verified to be non-zero to protect against low-order point attacks.
- **AEAD Nonces:** Must be exactly 12 bytes. Nonces for messaging are managed by the Double Ratchet layer.
- **Authentication Tags:** ChaCha20-Poly1305 uses a 16-byte (128-bit) tag.

## 4. Implementation Details
- **Provider:** Bouncy Castle 1.85.2 (Lightweight API).
- **Environment:** Android SDK 36 (Min SDK 26).
- **Audit Tool:** `ForensicVerificationTest` (Internal only, used during Milestone 2).

## 5. KAT Status (Milestone 2 - Frozen)
All primitives listed in section 2 have passed 100% of their respective RFC KAT vectors in the target runtime environment.
