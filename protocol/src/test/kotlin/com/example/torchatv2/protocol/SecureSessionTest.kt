package com.example.torchatv2.protocol

import com.example.torchatv2.crypto.*
import com.example.torchatv2.domain.Identity
import org.junit.Assert.*
import org.junit.Test

class SecureSessionTest {

    private val keyGenerator = BouncyCastleKeyPairGenerator()
    private val signatureProvider = BouncyCastleSignatureProvider()
    private val hkdfProvider = BouncyCastleHkdfProvider()
    private val keyAgreement = BouncyCastleKeyAgreementProvider()
    private val aeadProvider = BouncyCastleAeadProvider()

    @Test
    fun testFullSessionLifecycle() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val bobId = Identity.generate(keyGenerator, signatureProvider)

        val alice = SecureSession(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)
        val bob = SecureSession(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)

        // 1. Handshake
        val event1 = alice.startInitiator()
        assertTrue(event1 is SessionEvent.HandshakeProduced)
        val m1 = (event1 as SessionEvent.HandshakeProduced).data

        val eventsBob1 = bob.handleIncoming(m1)
        assertEquals(1, eventsBob1.size)
        assertTrue(eventsBob1[0] is SessionEvent.HandshakeProduced)
        val m2 = (eventsBob1[0] as SessionEvent.HandshakeProduced).data

        val eventsAlice1 = alice.handleIncoming(m2)
        assertEquals(2, eventsAlice1.size)
        assertTrue(eventsAlice1[0] is SessionEvent.HandshakeProduced)
        assertTrue(eventsAlice1[1] is SessionEvent.StateChanged)
        assertEquals(SessionState.ESTABLISHED, alice.getState())
        val m3 = (eventsAlice1[0] as SessionEvent.HandshakeProduced).data

        val eventsBob2 = bob.handleIncoming(m3)
        assertEquals(1, eventsBob2.size)
        assertTrue(eventsBob2[0] is SessionEvent.StateChanged)
        assertEquals(SessionState.ESTABLISHED, bob.getState())

        // 2. Data Transfer
        val p1 = "Hello Bob!".toByteArray()
        val e1 = alice.send(p1)
        
        val eventsBob3 = bob.handleIncoming(e1)
        assertEquals(1, eventsBob3.size)
        assertTrue(eventsBob3[0] is SessionEvent.PlaintextReceived)
        assertArrayEquals(p1, (eventsBob3[0] as SessionEvent.PlaintextReceived).data)

        val p2 = "Hi Alice!".toByteArray()
        val e2 = bob.send(p2)
        
        val eventsAlice2 = alice.handleIncoming(e2)
        assertEquals(1, eventsAlice2.size)
        assertTrue(eventsAlice2[0] is SessionEvent.PlaintextReceived)
        assertArrayEquals(p2, (eventsAlice2[0] as SessionEvent.PlaintextReceived).data)
    }

    @Test(expected = IllegalStateException::class)
    fun testSendBeforeEstablished() {
        val id = Identity.generate(keyGenerator, signatureProvider)
        val session = SecureSession(id, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)
        session.send("test".toByteArray())
    }

    @Test
    fun testHandshakeFailure() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val alice = SecureSession(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)

        val m1 = (alice.startInitiator() as SessionEvent.HandshakeProduced).data
        val bobId = Identity.generate(keyGenerator, signatureProvider)
        val bob = SecureSession(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)
        
        val m2 = (bob.handleIncoming(m1)[0] as SessionEvent.HandshakeProduced).data
        
        // Corrupt m2
        m2[100] = (m2[100].toInt() xor 0xFF).toByte()
        
        val events = alice.handleIncoming(m2)
        assertTrue(events[0] is SessionEvent.Error)
        assertEquals(SessionState.FAILED, alice.getState())
    }

    @Test
    fun testDestroySession() {
        val id = Identity.generate(keyGenerator, signatureProvider)
        val session = SecureSession(id, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)
        session.destroy()
        assertEquals(SessionState.CLOSED, session.getState())
        
        try {
            session.startInitiator()
            fail("Should throw IllegalStateException")
        } catch (e: IllegalStateException) { /* Expected */ }
    }
}
