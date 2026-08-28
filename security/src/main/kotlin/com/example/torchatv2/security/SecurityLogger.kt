package com.example.torchatv2.security

interface SecurityLogger {
    fun logSecurityEvent(event: SecurityEvent)
}

enum class SecurityEvent {
    PAIRING_STARTED,
    PAIRING_FAILED,
    SESSION_CREATED,
    SESSION_RESET,
    MESSAGE_SENT,
    MESSAGE_RECEIVED,
    AUTHENTICATION_FAILED
}
