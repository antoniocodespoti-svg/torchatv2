package com.example.torchatv2.crypto

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

class BouncyCastleAeadProvider : AeadProvider {

    override fun encrypt(
        key: AeadKey,
        nonce: Nonce,
        plaintext: ByteArray,
        aad: ByteArray
    ): ByteArray {
        val cipher = ChaCha20Poly1305()
        val params = AEADParameters(KeyParameter(key.copyBytes()), 128, nonce.copyBytes(), aad)
        cipher.init(true, params)
        
        val output = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
        val finalLen = cipher.doFinal(output, len)
        
        val total = len + finalLen
        return if (total == output.size) output else output.copyOf(total)
    }

    override fun decrypt(
        key: AeadKey,
        nonce: Nonce,
        ciphertext: ByteArray,
        aad: ByteArray
    ): ByteArray {
        try {
            val cipher = ChaCha20Poly1305()
            val params = AEADParameters(KeyParameter(key.copyBytes()), 128, nonce.copyBytes(), aad)
            cipher.init(false, params)
            
            val output = ByteArray(cipher.getOutputSize(ciphertext.size))
            val len = cipher.processBytes(ciphertext, 0, ciphertext.size, output, 0)
            val finalLen = cipher.doFinal(output, len)
            
            val total = len + finalLen
            return if (total == output.size) output else output.copyOf(total)
        } catch (e: Exception) {
            throw CryptoError.AuthenticationFailed
        }
    }
}
