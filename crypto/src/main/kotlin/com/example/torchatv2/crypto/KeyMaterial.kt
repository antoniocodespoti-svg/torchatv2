package com.example.torchatv2.crypto

import java.util.Arrays

/**
 * Interface for disposable cryptographic material.
 */
interface Disposable {
    fun destroy()
    fun isDestroyed(): Boolean
}

abstract class BaseKeyMaterial(
    private var bytes: ByteArray?
) : Disposable {

    protected fun getInternalBytes(): ByteArray {
        val b = bytes ?: throw CryptoError.KeyDestroyed
        return b
    }

    override fun destroy() {
        bytes?.let { Arrays.fill(it, 0.toByte()) }
        bytes = null
    }

    override fun isDestroyed(): Boolean = bytes == null

    override fun toString(): String = "[PROTECTED KEY]"

    /**
     * Clones the internal bytes.
     */
    fun copyBytes(): ByteArray = getInternalBytes().copyOf()
}

class Ed25519PrivateKey(seed: ByteArray) : BaseKeyMaterial(seed.copyOf()) {
    init {
        require(seed.size == 32) { "Ed25519 private key seed must be 32 bytes" }
    }
}

class Ed25519PublicKey(data: ByteArray) : BaseKeyMaterial(data.copyOf()) {
    init {
        require(data.size == 32) { "Ed25519 public key must be 32 bytes" }
    }
}

class X25519PrivateKey(data: ByteArray) : BaseKeyMaterial(data.copyOf()) {
    init {
        require(data.size == 32) { "X25519 private key must be 32 bytes" }
    }
}

class X25519PublicKey(data: ByteArray) : BaseKeyMaterial(data.copyOf()) {
    init {
        require(data.size == 32) { "X25519 public key must be 32 bytes" }
    }
}

class AeadKey(data: ByteArray) : BaseKeyMaterial(data.copyOf()) {
    init {
        require(data.size == 32) { "AEAD key must be 32 bytes" }
    }
}

class Nonce(data: ByteArray) : BaseKeyMaterial(data.copyOf()) {
    init {
        require(data.size == 12) { "Nonce must be 12 bytes" }
    }
}

data class Ed25519KeyPair(val privateKey: Ed25519PrivateKey, val publicKey: Ed25519PublicKey)
data class X25519KeyPair(val privateKey: X25519PrivateKey, val publicKey: X25519PublicKey)
