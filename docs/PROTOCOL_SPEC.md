# TorChatV2 Protocol Specification
**Version 1.0 / Protocol V1 (Synchronous Direct-Connect)**

## 1. Scope and Security Goals
This specification defines the communication protocol for TorChatV2 V1, designed for secure, synchronous, peer-to-peer messaging over the Tor network.

### 1.1 Security Goals
*   **Mutual Authentication:** Both participants must cryptographically prove their identity.
*   **Initial Forward Secrecy:** Compromise of long-term keys does not compromise past sessions.
*   **Post-Compromise Security:** The Double Ratchet algorithm ensures that even if a session state is compromised, security is recovered after a successful round-trip.
*   **Replay Protection:** Use of random nonces and session counters ensures that messages cannot be replayed.
*   **Metadata Minimization:** The protocol aims to leak minimal information about the participants to the transport layer.

### 1.2 Threat Model
*   **Adversary Capabilities:** The adversary can observe, block, delay, and modify transport-level packets. The adversary may compromise individual session keys or, in extreme cases, long-term identity keys.
*   **Tor Transport:** The protocol assumes Tor provides anonymity and a reliable, ordered stream. TorChatV2 protects the content and integrity of the communication even if the Tor circuit is compromised.
*   **KCI (Key Compromise Impersonation):** The compromise of an initiator's static agreement key (SK_A) MUST NOT allow an adversary to impersonate a remote peer (Bob) to the initiator (Alice). Mutual authentication and binding of ephemeral keys to identities provide this protection.

---

## 2. Cryptographic Primitives
Implementations MUST use the following primitives as validated in the `:crypto` module:
*   **Identity & Signatures:** Ed25519 (RFC 8032).
*   **Key Agreement:** X25519 (RFC 7748).
*   **Hashing:** SHA-256 (FIPS 180-4).
*   **MAC:** HMAC-SHA256 (RFC 2104).
*   **KDF:** HKDF-SHA256 (RFC 5869).
*   **AEAD:** ChaCha20-Poly1305 (RFC 8439).

---

## 3. Encoding Rules
*   **Byte Order:** All multi-byte integers MUST be encoded in **Big-Endian**.
*   **Public Keys:** Encoded as 32-byte raw arrays.
*   **Signatures:** Encoded as 64-byte raw arrays.
*   **Concatenation:** Fields are concatenated directly unless a length-prefix is specified.
*   **Domain Separators:** Used in signatures and KDFs to prevent cross-protocol attacks.

---

## 4. Identity
An Identity consists of two separate key pairs. Ed25519 is used for identity verification, while a separate X25519 pair is used for key agreement.

*   **LongTermIdentity (IK):** Ed25519 key pair.
*   **AgreementIdentity (SK):** X25519 key pair.
*   **Fingerprint:** `SHA-256(IK_pub)`. Used as the primary user-facing identifier.
*   **IdentitySignature:** A binding proof:
    `Ed25519Sign(IK_priv, "TC-V1-IdBinding" || IK_pub || SK_pub)`
    This signature MUST be verified before accepting any `SK_pub` as belonging to `IK_pub`.

---

## 5. Handshake (3-Message Sigma-I)
The handshake establishes a shared secret between Alice (Initiator) and Bob (Responder).

### 5.1 Message Definitions
*   **M1 (Alice -> Bob):** `Version(1) | RoleA(0x01) | NA(16) | EKA_pub(32) | IKA_pub(32) | SKA_pub(32) | IdSigA(64)`
*   **M2 (Bob -> Alice):** `Version(1) | RoleB(0x02) | NB(16) | EKB_pub(32) | IKB_pub(32) | SKB_pub(32) | IdSigB(64) | SigB(64)`
*   **M3 (Alice -> Bob):** `Version(1) | RoleA(0x01) | SigA(64)`

### 5.2 Transcript and Signature Binding
To avoid circular dependencies, the handshake signatures are defined as follows:
*   `M1` = Full Initiation message.
*   `M2_pre` = M2 up to (but not including) `SigB`.
*   `TH1 = SHA-256(M1)`
*   `TH2 = SHA-256(M1 || M2_pre)`
*   `SigB = Ed25519Sign(IKB_priv, "TC-V1-Handshake-B" || TH2)`
*   `M3_pre` = M3 up to (but not including) `SigA`.
*   `SigA = Ed25519Sign(IKA_priv, "TC-V1-Handshake-A" || SHA-256(M1 || M2 || M3_pre))`
*   `TH3 = SHA-256(M1 || M2 || M3)` (Final authenticated transcript).

---

## 6. Key Agreement and Derivation

### 6.1 Triple Diffie-Hellman (3DH)
Upon receiving the necessary public keys, peers calculate:
1.  `DH1 = X25519(EKA_priv, EKB_pub)`
2.  `DH2 = X25519(EKA_priv, SKB_pub)`
3.  `DH3 = X25519(SKA_priv, EKB_pub)`
*   `IKM = DH1 || DH2 || DH3` (96 bytes).

If any DH output is all-zero or an error occurs, the session MUST be terminated immediately.

### 6.2 KDF Sequence
1.  `HandshakeSecret = HKDF-Extract(salt = TH2, IKM = IKM)`
2.  `SessionSecret = HKDF-Expand(HandshakeSecret, info = "TC-V1-SessionSecret" || TH3, len = 32)`
3.  `RootKey = HKDF-Expand(SessionSecret, info = "TC-V1-RootKey", len = 32)`
4.  `SessionID = HKDF-Expand(SessionSecret, info = "TC-V1-SessionID", len = 16)`

---

## 7. Double Ratchet
After the handshake, participants use the Double Ratchet to secure further communication.

*   **Initial State:** Alice is the first sender.
*   **Root Key (RK):** Initialized from `RootKey` derived in the handshake.
*   **DH Ratchet:** Triggered when a message is received with a new `RatchetPubKey`.
*   **Symmetric Ratchet:** Separate `Sending` and `Receiving` chains.
*   **Message Keys (MK):** Derived from Chain Keys:
    *   `MK_i = HMAC-SHA256(CK_i, 0x01)`
    *   `CK_{i+1} = HMAC-SHA256(CK_i, 0x02)`
*   **Skipped Messages:** Implementations MUST support skipping up to `MAX_SKIP = 100` messages. Skipped keys are stored in `MKSKIPPED` and MUST be deleted immediately after use or session termination.

---

## 8. Authenticated Encryption (AEAD)
*   **Algorithm:** ChaCha20-Poly1305.
*   **Key:** 32-byte `MessageKey` (MK).
*   **Nonce (12 bytes):** `00 00 00 00 || uint64_be(N)`.
    *   `N` is the message number in the current chain.
    *   Uniqueness is guaranteed because each `MK` is used exactly once.

---

## 9. Message Format
All Data messages (MsgType 0x02) use the following binary format:

### 9.1 Header (62 bytes)
| Field | Offset | Length | Description |
| :--- | :--- | :--- | :--- |
| Version | 0 | 1 | Protocol version (0x01) |
| MessageType | 1 | 1 | Type (0x02 for Data) |
| SessionID | 2 | 16 | Unique session identifier |
| RatchetPubKey | 18 | 32 | Current DH Ratchet public key |
| PN | 50 | 4 | Messages in previous DH chain |
| N | 54 | 4 | Message number in current chain |
| CiphertextLen | 58 | 4 | Length of Ciphertext (excludes Tag) |

### 9.2 Associated Data (AD)
`AD` consists of the first 58 bytes of the header (Version through N). `CiphertextLen` is excluded from AD to facilitate early buffer allocation.

### 9.3 Body
`Ciphertext` followed by a 16-byte `AuthTag`.

---

## 10. Receive Processing
1.  Parse header and verify `Version` and `SessionID`.
2.  If `(RatchetPubKey, N)` exists in `MKSKIPPED`, use the stored `MK`.
3.  If `RatchetPubKey` is new:
    *   Ensure `N` is within `MAX_SKIP` of `Nr`.
    *   Derive and store skipped keys for the old chain.
    *   Perform DH Ratchet to advance `RK` and generate new `CKr`.
4.  If `RatchetPubKey` is current, advance `CKr` to message `N`, storing intermediate keys in `MKSKIPPED`.
5.  Derive `MK`, decrypt, and verify `AuthTag`.
6.  **MUST NOT** accept plaintext if authentication fails. An authentication error MUST terminate the session.
7.  Immediately delete the used `MK`.

---

## 11. Session Lifecycle
*   **Tor Transport:** The protocol assumes a reliable, ordered stream.
*   **Disconnection:** Upon loss of the Tor circuit, the session MUST be destroyed. No resumption is allowed in V1.
*   **Zeroization:** Ephemeral private keys, DH outputs, HandshakeSecret, and all MessageKeys MUST be zeroized (`Arrays.fill(0)`) as soon as they are no longer required.

---

## 12. Security Invariants
*   **Key Uniqueness:** Never reuse a `MessageKey`.
*   **Nonce Safety:** Never reuse a `(Key, Nonce)` pair.
*   **Authentication First:** Verify `AuthTag` before any plaintext processing.
*   **Transcript Binding:** All handshake parameters MUST be bound to the transcript hash.
*   **Fail-safe:** Any cryptographic error is fatal to the session.
*   **Transport Isolation:** Identity is verified via Ed25519, independent of the `.onion` address.

---

## 13. Interoperability Test Vectors
*(To be populated in future milestones)*

---

## 14. Out of Scope for V1
*   Message Padding (Traffic Analysis defense).
*   Header Encryption.
*   Session Resumption.
*   Multi-device support.

---
## Implementation Boundary
This specification is normative. Future Kotlin implementations in the `:protocol`, `:ratchet`, and `:domain` modules MUST strictly adhere to these rules. Any deviation from the defined byte sequences or cryptographic order of operations will break compatibility and security.
