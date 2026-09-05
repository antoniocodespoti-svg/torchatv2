package com.example.torchatv2.transport

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.LinkedList

/**
 * Modes of operation for the state-aware framer.
 */
enum class FramingMode {
    HANDSHAKE_M1,
    HANDSHAKE_M2,
    HANDSHAKE_M3,
    DATA
}

/**
 * State-aware framer that reconstructs messages from a stream of bytes.
 * It is stateless with respect to cryptography and handles only the framing boundaries.
 */
class MessageFramer(
    private var maxFrameSize: Int = Int.MAX_VALUE
) {
    private var mode = FramingMode.HANDSHAKE_M1
    private val buffer = LinkedList<Byte>()

    companion object {
        private const val M1_SIZE = 178
        private const val M2_SIZE = 242
        private const val M3_SIZE = 66
        private const val DATA_HEADER_SIZE = 62
        private const val AUTH_TAG_SIZE = 16
        private const val CIPHERTEXT_LEN_OFFSET = 58
    }

    /**
     * Sets the current framing mode.
     */
    fun setMode(newMode: FramingMode) {
        this.mode = newMode
    }

    /**
     * Resets the internal buffer.
     */
    fun reset() {
        buffer.clear()
    }

    /**
     * Configures the maximum allowed frame size.
     */
    fun setMaxFrameSize(size: Int) {
        this.maxFrameSize = size
    }

    /**
     * Processes incoming bytes and returns a list of reconstructed messages.
     */
    fun onBytesReceived(bytes: ByteArray): List<ByteArray> {
        val result = mutableListOf<ByteArray>()
        for (b in bytes) {
            buffer.add(b)
        }

        while (true) {
            val frame = tryPopFrame() ?: break
            result.add(frame)
        }
        return result
    }

    private fun tryPopFrame(): ByteArray? {
        val expectedSize = when (mode) {
            FramingMode.HANDSHAKE_M1 -> M1_SIZE
            FramingMode.HANDSHAKE_M2 -> M2_SIZE
            FramingMode.HANDSHAKE_M3 -> M3_SIZE
            FramingMode.DATA -> {
                if (buffer.size < DATA_HEADER_SIZE) return null
                
                // Peek ciphertext length at offset 58
                val lenBytes = ByteArray(4)
                for (i in 0 until 4) {
                    lenBytes[i] = buffer[CIPHERTEXT_LEN_OFFSET + i]
                }
                val ciphertextLen = ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).int
                
                if (ciphertextLen < 0) {
                    throw IllegalArgumentException("Negative ciphertext length: $ciphertextLen")
                }

                // Total = Header (62) + Ciphertext + Tag (16)
                val total = DATA_HEADER_SIZE.toLong() + ciphertextLen + AUTH_TAG_SIZE
                if (total > maxFrameSize) {
                    throw IllegalArgumentException("Frame size $total exceeds maxFrameSize $maxFrameSize")
                }
                if (total > Int.MAX_VALUE) {
                    throw ArithmeticException("Frame size exceeds Int.MAX_VALUE")
                }
                total.toInt()
            }
        }

        if (buffer.size < expectedSize) return null

        val frame = ByteArray(expectedSize)
        for (i in 0 until expectedSize) {
            frame[i] = buffer.removeFirst()
        }
        return frame
    }
}
