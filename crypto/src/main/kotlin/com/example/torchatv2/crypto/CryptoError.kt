package com.example.torchatv2.crypto

sealed class CryptoError : Exception() {
    object InvalidKey : CryptoError()
    object InvalidNonce : CryptoError()
    object InvalidInput : CryptoError()
    object AuthenticationFailed : CryptoError()
    object InvalidSignature : CryptoError()
    object KeyAgreementError : CryptoError()
    object KeyDestroyed : CryptoError()
    data class ProviderError(val detail: String) : CryptoError()
    
    override fun toString(): String = this.javaClass.simpleName
}
