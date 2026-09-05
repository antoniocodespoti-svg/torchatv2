package com.example.torchatv2.protocol

import com.example.torchatv2.crypto.*
import com.example.torchatv2.domain.Identity
import org.junit.Assert.*
import org.junit.Test

class HandshakeTest {

    private val keyGenerator = BouncyCastleKeyPairGenerator()
    private val signatureProvider = BouncyCastleSignatureProvider()
    private val hkdfProvider = BouncyCastleHkdfProvider()
    private val keyAgreement = BouncyCastleKeyAgreementProvider()

    @Test
    fun testHandshakeSuccess() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val bobId = Identity.generate(keyGenerator, signatureProvider)

        val alice = HandshakeInitiator(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        val bob = HandshakeResponder(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)

        // 1. Alice -> Bob (M1)
        val m1 = alice.start()
        assertEquals(178, m1.size)

        // 2. Bob processes M1 -> M2
        val m2 = bob.processM1(m1)
        assertEquals(242, m2.size)

        // 3. Alice processes M2 -> M3
        val m3 = alice.processM2(m2)
        assertEquals(66, m3.size)

        // 4. Bob processes M3
        bob.processM3(m3)

        // 5. Verify Results
        val aliceResult = alice.getResult()
        val bobResult = bob.getResult()

        assertArrayEquals("RootKey mismatch", aliceResult.rootKey, bobResult.rootKey)
        assertArrayEquals("SessionID mismatch", aliceResult.sessionId, bobResult.sessionId)
        assertEquals(16, aliceResult.sessionId.size)
        assertEquals(32, aliceResult.rootKey.size)

        // Remote Identities
        assertArrayEquals(bobId.ikPublic.copyBytes(), aliceResult.remotePeerIdentity.ikPublic.copyBytes())
        assertArrayEquals(aliceId.ikPublic.copyBytes(), bobResult.remotePeerIdentity.ikPublic.copyBytes())
        
        // Ratchet Keys
        // aliceResult.initialRemoteRatchetKey should be Bob's EKB
        // bobResult.initialRemoteRatchetKey should be Alice's EKA
    }

    @Test(expected = HandshakeError.InvalidSignature::class)
    fun testHandshakeSigBFailure() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val bobId = Identity.generate(keyGenerator, signatureProvider)

        val alice = HandshakeInitiator(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        val bob = HandshakeResponder(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)

        val m1 = alice.start()
        val m2 = bob.processM1(m1)
        
        // Corrupt SigB in M2
        m2[241] = (m2[241].toInt() xor 0xFF).toByte()
        
        alice.processM2(m2)
    }

    @Test(expected = HandshakeError.InvalidSignature::class)
    fun testHandshakeSigAFailure() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val bobId = Identity.generate(keyGenerator, signatureProvider)

        val alice = HandshakeInitiator(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        val bob = HandshakeResponder(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)

        val m1 = alice.start()
        val m2 = bob.processM1(m1)
        val m3 = alice.processM2(m2)
        
        // Corrupt SigA in M3
        m3[65] = (m3[65].toInt() xor 0xFF).toByte()
        
        bob.processM3(m3)
    }

    @Test(expected = HandshakeError.InvalidVersion::class)
    fun testHandshakeVersionFailure() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val alice = HandshakeInitiator(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        
        val m1 = alice.start()
        m1[0] = 0x02 // Invalid version
        
        val bobId = Identity.generate(keyGenerator, signatureProvider)
        val bob = HandshakeResponder(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        bob.processM1(m1)
    }

    @Test(expected = HandshakeError.InvalidRole::class)
    fun testHandshakeRoleFailure() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val alice = HandshakeInitiator(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        
        val m1 = alice.start()
        m1[1] = 0x02 // Wrong role
        
        val bobId = Identity.generate(keyGenerator, signatureProvider)
        val bob = HandshakeResponder(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        bob.processM1(m1)
    }

    @Test(expected = HandshakeError.InvalidMessageLength::class)
    fun testHandshakeLengthFailure() {
        val bobId = Identity.generate(keyGenerator, signatureProvider)
        val bob = HandshakeResponder(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        bob.processM1(ByteArray(100))
    }

    @Test(expected = HandshakeError.InvalidState::class)
    fun testHandshakeStateReuseFailure() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val alice = HandshakeInitiator(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
        alice.start()
        alice.start() // Should throw
    }
}
