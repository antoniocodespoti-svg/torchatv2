package com.example.torchatv2.protocol

import com.example.torchatv2.ratchet.RatchetHeader
import com.example.torchatv2.ratchet.RatchetMessage
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MessageCodecTest {

    private val sampleSessionId = ByteArray(16) { i -> i.toByte() }
    private val sampleRatchetKey = ByteArray(32) { i -> (i + 100).toByte() }
    private val sampleCiphertext = "Secret Message".toByteArray()
    private val sampleAuthTag = ByteArray(16) { 0xAA.toByte() }

    @Test
    fun testRoundTrip() {
        val header = RatchetHeader(
            sessionId = sampleSessionId,
            ratchetPubKey = sampleRatchetKey,
            pn = 1234,
            n = 5678
        )
        val original = RatchetMessage(header, sampleCiphertext, sampleAuthTag)
        
        val encoded = MessageCodec.encode(original)
        val decoded = MessageCodec.decode(encoded)
        
        assertEquals(original.header, decoded.header)
        assertArrayEquals(original.ciphertext, decoded.ciphertext)
        assertArrayEquals(original.authTag, decoded.authTag)
    }

    @Test
    fun testHeaderByteLevel() {
        val pn = 0x11223344
        val n = 0x55667788
        val header = RatchetHeader(
            sessionId = sampleSessionId,
            ratchetPubKey = sampleRatchetKey,
            pn = pn,
            n = n
        )
        val msg = RatchetMessage(header, sampleCiphertext, sampleAuthTag)
        val encoded = MessageCodec.encode(msg)

        // Offset 0: Version 0x01
        assertEquals(0x01.toByte(), encoded[0])
        // Offset 1: MessageType 0x02
        assertEquals(0x02.toByte(), encoded[1])
        
        // Offset 2: SessionID (16 bytes)
        val sessionBuffer = ByteArray(16)
        System.arraycopy(encoded, 2, sessionBuffer, 0, 16)
        assertArrayEquals(sampleSessionId, sessionBuffer)
        
        // Offset 18: RatchetPubKey (32 bytes)
        val keyBuffer = ByteArray(32)
        System.arraycopy(encoded, 18, keyBuffer, 0, 32)
        assertArrayEquals(sampleRatchetKey, keyBuffer)
        
        // Offset 50: PN (4 bytes Big-Endian)
        val pnBuffer = ByteBuffer.wrap(encoded, 50, 4).order(ByteOrder.BIG_ENDIAN)
        assertEquals(pn, pnBuffer.getInt())
        
        // Offset 54: N (4 bytes Big-Endian)
        val nBuffer = ByteBuffer.wrap(encoded, 54, 4).order(ByteOrder.BIG_ENDIAN)
        assertEquals(n, nBuffer.getInt())
        
        // Offset 58: CiphertextLen (4 bytes Big-Endian)
        val lenBuffer = ByteBuffer.wrap(encoded, 58, 4).order(ByteOrder.BIG_ENDIAN)
        assertEquals(sampleCiphertext.size, lenBuffer.getInt())
        
        // Total header size check
        assertEquals(62 + sampleCiphertext.size + 16, encoded.size)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidVersion() {
        val encoded = MessageCodec.encode(createSampleMessage())
        encoded[0] = 0x99.toByte()
        MessageCodec.decode(encoded)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidMessageType() {
        val encoded = MessageCodec.encode(createSampleMessage())
        encoded[1] = 0x01.toByte() // Handshake type
        MessageCodec.decode(encoded)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testTruncatedHeader() {
        MessageCodec.decode(ByteArray(61))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testTruncatedBody() {
        val encoded = MessageCodec.encode(createSampleMessage())
        MessageCodec.decode(encoded.copyOf(encoded.size - 1))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testExtraBytes() {
        val encoded = MessageCodec.encode(createSampleMessage())
        MessageCodec.decode(encoded + byteArrayOf(0x00))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidSessionIdSize() {
        val header = RatchetHeader(ByteArray(15), sampleRatchetKey, 0, 0)
        MessageCodec.encode(RatchetMessage(header, sampleCiphertext, sampleAuthTag))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidRatchetKeySize() {
        val header = RatchetHeader(sampleSessionId, ByteArray(31), 0, 0)
        MessageCodec.encode(RatchetMessage(header, sampleCiphertext, sampleAuthTag))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidAuthTagSize() {
        val header = createSampleHeader()
        MessageCodec.encode(RatchetMessage(header, sampleCiphertext, ByteArray(15)))
    }

    private fun createSampleHeader() = RatchetHeader(sampleSessionId, sampleRatchetKey, 1, 1)
    private fun createSampleMessage() = RatchetMessage(createSampleHeader(), sampleCiphertext, sampleAuthTag)
}
