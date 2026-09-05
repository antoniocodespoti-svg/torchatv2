package com.example.torchatv2.transport

/**
 * Represents a Tor Onion Endpoint (e.g., v3 address).
 */
data class OnionEndpoint(val address: String) {
    init {
        require(address.endsWith(".onion")) { "Invalid onion address" }
        // V3 addresses are 56 characters + .onion = 62 characters
        require(address.length == 62) { "Only Onion v3 addresses are supported" }
    }
}

/**
 * State of the Tor daemon bootstrap process.
 */
sealed class TorState {
    object Idle : TorState()
    data class Bootstrapping(val progress: Int) : TorState()
    object Ready : TorState()
    data class Error(val throwable: Throwable) : TorState()
}

/**
 * Manages the lifecycle of the Tor daemon.
 */
interface TorManager {
    fun start()
    fun stop()
    fun getState(): TorState
}

/**
 * Manages the local Onion Service.
 */
interface OnionServiceManager {
    fun startService()
    fun stopService()
    fun getLocalEndpoint(): OnionEndpoint?
}
