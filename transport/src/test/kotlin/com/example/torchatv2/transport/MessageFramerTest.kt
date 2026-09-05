package com.example.torchatv2.transport

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MessageFramerTest {

    @Test
    fun testHandshakeM1Frame() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.HANDSHAKE_M1)
        
        val input = ByteArray(178) { i -> i.toByte() }
        val result = framer.onBytesReceived(input)
        
        assertEquals(1, result.size)
        assertArrayEquals(input, result[0])
    }

    @Test
    fun testHandshakeM2Frame() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.HANDSHAKE_M2)
        
        val input = ByteArray(242) { i -> i.toByte() }
        val result = framer.onBytesReceived(input)
        
        assertEquals(1, result.size)
        assertArrayEquals(input, result[0])
    }

    @Test
    fun testHandshakeM3Frame() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.HANDSHAKE_M3)
        
        val input = ByteArray(66) { i -> i.toByte() }
        val result = framer.onBytesReceived(input)
        
        assertEquals(1, result.size)
        assertArrayEquals(input, result[0])
    }

    @Test
    fun testDataFrame() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.DATA)
        
        val ciphertextLen = 100
        val input = createFakeDataMessage(ciphertextLen)
        
        val result = framer.onBytesReceived(input)
        
        assertEquals(1, result.size)
        assertArrayEquals(input, result[0])
    }

    @Test
    fun testPartialHeader() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.DATA)
        
        val ciphertextLen = 100
        val fullMsg = createFakeDataMessage(ciphertextLen)
        
        // Send first 30 bytes
        val result1 = framer.onBytesReceived(fullMsg.copyOfRange(0, 30))
        assertTrue(result1.isEmpty())
        
        // Send next 40 bytes (header complete + part of body)
        val result2 = framer.onBytesReceived(fullMsg.copyOfRange(30, 70))
        assertTrue(result2.isEmpty())
        
        // Send remaining
        val result3 = framer.onBytesReceived(fullMsg.copyOfRange(70, fullMsg.size))
        assertEquals(1, result3.size)
        assertArrayEquals(fullMsg, result3[0])
    }

    @Test
    fun testOneByteAtATime() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.HANDSHAKE_M1)
        val input = ByteArray(178) { i -> i.toByte() }
        
        for (i in 0 until 177) {
            assertTrue(framer.onBytesReceived(byteArrayOf(input[i])).isEmpty())
        }
        val result = framer.onBytesReceived(byteArrayOf(input[177]))
        assertEquals(1, result.size)
        assertArrayEquals(input, result[0])
    }

    @Test
    fun testMultipleFrames() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.HANDSHAKE_M3)
        val m3 = ByteArray(66) { 0x03.toByte() }
        
        val result = framer.onBytesReceived(m3 + m3)
        assertEquals(2, result.size)
        assertArrayEquals(m3, result[0])
        assertArrayEquals(m3, result[1])
    }

    @Test
    fun testBytesAfterFramePreserved() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.HANDSHAKE_M3)
        val m3 = ByteArray(66) { 0x03.toByte() }
        
        val result = framer.onBytesReceived(m3 + byteArrayOf(0x01, 0x02))
        assertEquals(1, result.size)
        assertArrayEquals(m3, result[0])
        
        framer.setMode(FramingMode.DATA)
        // Header with ciphertextLen = 0 (total size = 62 + 0 + 16 = 78)
        val header = ByteArray(62)
        header[0] = 0x01
        header[1] = 0x02
        ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).putInt(58, 0)
        val body = ByteArray(16) { 0xAA.toByte() }
        val dataMsg = header + body
        
        // First 2 bytes of dataMsg were already in buffer (0x01, 0x02)
        val result2 = framer.onBytesReceived(dataMsg.copyOfRange(2, dataMsg.size))
        assertEquals(1, result2.size)
        assertArrayEquals(dataMsg, result2[0])
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidCiphertextLen() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.DATA)
        
        val header = ByteArray(62)
        ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).putInt(58, -1)
        
        framer.onBytesReceived(header)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testOversizedFrame() {
        val framer = MessageFramer(maxFrameSize = 100)
        framer.setMode(FramingMode.DATA)
        
        val header = ByteArray(62)
        ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).putInt(58, 50) // Total = 62+50+16 = 128
        
        framer.onBytesReceived(header)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testFrameSizeExceedsIntMaxValue() {
        val framer = MessageFramer(maxFrameSize = Int.MAX_VALUE)
        framer.setMode(FramingMode.DATA)
        
        val header = ByteArray(62)
        // Set ciphertextLen to Int.MAX_VALUE
        ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).putInt(58, Int.MAX_VALUE)
        
        // Total = 62 + 2147483647 + 16 = 2147483725 (> Int.MAX_VALUE)
        framer.onBytesReceived(header)
    }

    @Test
    fun testReset() {
        val framer = MessageFramer()
        framer.setMode(FramingMode.HANDSHAKE_M1)
        framer.onBytesReceived(ByteArray(100))
        framer.reset()
        
        val input = ByteArray(178) { 0x01.toByte() }
        assertEquals(1, framer.onBytesReceived(input).size)
    }

    private fun createFakeDataMessage(ciphertextLen: Int): ByteArray {
        val header = ByteArray(62)
        ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).putInt(58, ciphertextLen)
        val body = ByteArray(ciphertextLen + 16) { 0xBB.toByte() }
        return header + body
    }
}
