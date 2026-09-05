package com.example.torchatv2.transport

/**
 * Listener for events from a [TransportConnection].
 * Received data is guaranteed to be a complete frame as reconstructed by a framer.
 */
interface TransportListener {
    fun onDataReceived(data: ByteArray)
    fun onDisconnected()
    fun onError(throwable: Throwable)
}

/**
 * Abstraction for a byte-stream based connection (e.g., Tor stream).
 *
 * Contract:
 * - [send] must be serialized; concurrent calls must not result in interleaved bytes.
 * - All bytes of a message must be delivered to the stream before [send] returns normally.
 * - Implementations should handle buffering and partial writes to satisfy the stream semantics.
 */
interface TransportConnection {
    fun send(data: ByteArray)
    fun setListener(listener: TransportListener)
    fun close()
}
