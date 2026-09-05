package com.example.torchatv2.transport

import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * In-memory implementation of [TransportConnection] for testing and simulation.
 * Connects two endpoints without real networking.
 */
class InMemoryTransportConnection(
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
) : TransportConnection {
    private var listener: TransportListener? = null
    private var peer: InMemoryTransportConnection? = null
    private var isClosed = false

    /**
     * Connects this endpoint to another [InMemoryTransportConnection].
     */
    fun connectTo(other: InMemoryTransportConnection) {
        this.peer = other
        other.peer = this
    }

    override fun send(data: ByteArray) {
        if (isClosed) throw IllegalStateException("Connection closed")
        val peerRef = peer ?: throw IllegalStateException("Not connected")
        
        // Defensive copy to simulate network transfer
        val copy = data.copyOf()
        
        executor.execute {
            if (!peerRef.isClosed) {
                peerRef.listener?.onDataReceived(copy)
            }
        }
    }

    override fun setListener(listener: TransportListener) {
        this.listener = listener
    }

    override fun close() {
        if (isClosed) return
        isClosed = true
        peer?.let {
            it.isClosed = true
            it.listener?.onDisconnected()
        }
        listener?.onDisconnected()
        executor.shutdown()
    }
    
    /**
     * Internal method to simulate partial/fragmented reads.
     */
    fun sendFragmented(data: ByteArray, chunkSize: Int) {
        if (isClosed) throw IllegalStateException("Connection closed")
        val peerRef = peer ?: throw IllegalStateException("Not connected")
        
        executor.execute {
            var offset = 0
            while (offset < data.size && !peerRef.isClosed) {
                val end = (offset + chunkSize).coerceAtMost(data.size)
                val chunk = data.copyOfRange(offset, end)
                peerRef.listener?.onDataReceived(chunk)
                offset = end
            }
        }
    }
}
