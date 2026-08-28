package com.example.torchatv2.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import kotlin.math.min

class BouncyCastleHkdfProvider : HkdfProvider {

    override fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val hmac = HMac(SHA256Digest())
        // HKDF-Extract(salt, IKM) -> HMAC(key=salt, msg=IKM)
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(32) { 0 } else salt
        
        hmac.init(KeyParameter(actualSalt))
        hmac.update(ikm, 0, ikm.size)
        val prk = ByteArray(32)
        hmac.doFinal(prk, 0)
        return prk
    }

    override fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        // Manual RFC 5869 Expand implementation
        // T(0) = empty string
        // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        val okm = ByteArray(length)
        val hmac = HMac(SHA256Digest())
        hmac.init(KeyParameter(prk))

        var lastT = ByteArray(0)
        var generated = 0
        var counter = 1

        while (generated < length) {
            hmac.update(lastT, 0, lastT.size)
            hmac.update(info, 0, info.size)
            hmac.update(counter.toByte())
            
            val tI = ByteArray(32)
            hmac.doFinal(tI, 0)
            
            val toCopy = min(tI.size, length - generated)
            System.arraycopy(tI, 0, okm, generated, toCopy)
            
            generated += toCopy
            lastT = tI
            counter++
        }
        return okm
    }
}
