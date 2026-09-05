package com.example.torchatv2.ratchet

import com.example.torchatv2.crypto.X25519KeyPair
import com.example.torchatv2.crypto.X25519PublicKey
import java.util.Arrays

/**
 * Wrapper for ByteArray to use as Map key (content-based equality).
 */
data class ByteArrayKey(val data: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ByteArrayKey) return false
        return data.contentEquals(other.data)
    }
    override fun hashCode(): Int = data.contentHashCode()
}

/**
 * Index for skipped message keys.
 */
data class MessageKeyIndex(val ratchetPubKey: ByteArrayKey, val n: Int)

/**
 * Holder for a skipped message key with a timestamp.
 */
data class SkippedMessageKey(
    val key: ByteArray,
    val createdAt: Long = System.currentTimeMillis()
) {
    fun destroy() {
        Arrays.fill(key, 0)
    }
}

/**
 * Internal state of a Double Ratchet session.
 */
internal class RatchetState(
    var rootKey: ByteArray,
    var dhs: X25519KeyPair,
    var dhr: X25519PublicKey?,
    var cks: ByteArray?,
    var ckr: ByteArray?,
    var ns: Int = 0,
    var nr: Int = 0,
    var pn: Int = 0,
    val skippedKeys: MutableMap<MessageKeyIndex, SkippedMessageKey> = mutableMapOf()
) {
    fun destroy() {
        Arrays.fill(rootKey, 0)
        dhs.privateKey.destroy()
        cks?.let { Arrays.fill(it, 0) }
        ckr?.let { Arrays.fill(it, 0) }
        skippedKeys.values.forEach { it.destroy() }
        skippedKeys.clear()
    }
}

/**
 * Represents the Double Ratchet header in a message.
 */
data class RatchetHeader(
    val sessionId: ByteArray,
    val ratchetPubKey: ByteArray,
    val pn: Int,
    val n: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RatchetHeader) return false
        if (!sessionId.contentEquals(other.sessionId)) return false
        if (!ratchetPubKey.contentEquals(other.ratchetPubKey)) return false
        if (pn != other.pn) return false
        if (n != other.n) return false
        return true
    }

    override fun hashCode(): Int {
        var result = sessionId.contentHashCode()
        result = 31 * result + ratchetPubKey.contentHashCode()
        result = 31 * result + pn
        result = 31 * result + n
        return result
    }
}

/**
 * Result of an encryption operation.
 */
data class RatchetMessage(
    val header: RatchetHeader,
    val ciphertext: ByteArray,
    val authTag: ByteArray
)
