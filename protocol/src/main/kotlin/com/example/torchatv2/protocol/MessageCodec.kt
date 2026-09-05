package com.example.torchatv2.protocol

import com.example.torchatv2.ratchet.RatchetHeader
import com.example.torchatv2.ratchet.RatchetMessage
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Codec for Data Messages as defined in docs/PROTOCOL_SPEC.md section 9.
 */
object MessageCodec {
    private const val VERSION: Byte = 0x01
    private const val MSG_TYPE_DATA: Byte = 0x02
    
    private const val HEADER_SIZE = 62
    private const val AUTH_TAG_SIZE = 16
    
    private const val SESSION_ID_SIZE = 16
    private const val RATCHET_PUB_KEY_SIZE = 32

    /**
     * Encodes a RatchetMessage into a binary ByteArray.
     * Format: Header (62 bytes) | Ciphertext (var) | AuthTag (16 bytes)
     */
    fun encode(message: RatchetMessage): ByteArray {
        val header = message.header
        val ciphertext = message.ciphertext
        val authTag = message.authTag
        
        require(header.sessionId.size == SESSION_ID_SIZE) { "Invalid SessionID size" }
        require(header.ratchetPubKey.size == RATCHET_PUB_KEY_SIZE) { "Invalid RatchetPubKey size" }
        require(authTag.size == AUTH_TAG_SIZE) { "Invalid AuthTag size" }
        
        val ciphertextLen = ciphertext.size
        val totalSize = HEADER_SIZE + ciphertextLen + AUTH_TAG_SIZE
        
        val buffer = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN)
        
        // Header
        buffer.put(VERSION)
        buffer.put(MSG_TYPE_DATA)
        buffer.put(header.sessionId)
        buffer.put(header.ratchetPubKey)
        buffer.putInt(header.pn)
        buffer.putInt(header.n)
        buffer.putInt(ciphertextLen)
        
        // Body
        buffer.put(ciphertext)
        buffer.put(authTag)
        
        return buffer.array()
    }

    /**
     * Decodes a binary ByteArray into a RatchetMessage.
     * Performs structural validation.
     */
    fun decode(data: ByteArray): RatchetMessage {
        if (data.size < HEADER_SIZE + AUTH_TAG_SIZE) {
            throw IllegalArgumentException("Message too short")
        }
        
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        
        val version = buffer.get()
        if (version != VERSION) {
            throw IllegalArgumentException("Unsupported protocol version: $version")
        }
        
        val msgType = buffer.get()
        if (msgType != MSG_TYPE_DATA) {
            throw IllegalArgumentException("Unsupported message type: $msgType")
        }
        
        val sessionId = ByteArray(SESSION_ID_SIZE)
        buffer.get(sessionId)
        
        val ratchetPubKey = ByteArray(RATCHET_PUB_KEY_SIZE)
        buffer.get(ratchetPubKey)
        
        val pn = buffer.getInt()
        val n = buffer.getInt()
        
        val ciphertextLen = buffer.getInt()
        if (ciphertextLen < 0) {
            throw IllegalArgumentException("Invalid ciphertext length: $ciphertextLen")
        }
        
        val expectedTotalSize = HEADER_SIZE + ciphertextLen + AUTH_TAG_SIZE
        if (data.size != expectedTotalSize) {
            throw IllegalArgumentException("Message size mismatch. Expected $expectedTotalSize, got ${data.size}")
        }
        
        val ciphertext = ByteArray(ciphertextLen)
        buffer.get(ciphertext)
        
        val authTag = ByteArray(AUTH_TAG_SIZE)
        buffer.get(authTag)
        
        val header = RatchetHeader(
            sessionId = sessionId,
            ratchetPubKey = ratchetPubKey,
            pn = pn,
            n = n
        )
        
        return RatchetMessage(header, ciphertext, authTag)
    }
}
