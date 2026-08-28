package com.example.torchatv2.crypto

interface CryptoKeyGenerator {
    fun generateEd25519KeyPair(): Ed25519KeyPair
    fun generateX25519KeyPair(): X25519KeyPair
    
    /**
     * Deterministic generation for KAT and testing purposes.
     */
    fun generateEd25519KeyPairFromSeed(seed: ByteArray): Ed25519KeyPair
    fun generateX25519KeyPairFromSeed(seed: ByteArray): X25519KeyPair
}

interface KeyAgreementProvider {
    @Throws(CryptoError.KeyAgreementError::class)
    fun calculateX25519SharedSecret(privateKey: X25519PrivateKey, publicKey: X25519PublicKey): ByteArray
}

interface SignatureProvider {
    fun sign(privateKey: Ed25519PrivateKey, message: ByteArray): ByteArray
    fun verify(publicKey: Ed25519PublicKey, message: ByteArray, signature: ByteArray): Boolean
}

interface HkdfProvider {
    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray
}

interface AeadProvider {
    @Throws(CryptoError.AuthenticationFailed::class)
    fun encrypt(key: AeadKey, nonce: Nonce, plaintext: ByteArray, aad: ByteArray): ByteArray
    
    @Throws(CryptoError.AuthenticationFailed::class)
    fun decrypt(key: AeadKey, nonce: Nonce, ciphertext: ByteArray, aad: ByteArray): ByteArray
}
