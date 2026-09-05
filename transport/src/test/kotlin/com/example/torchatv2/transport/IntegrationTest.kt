package com.example.torchatv2.transport

import com.example.torchatv2.crypto.*
import com.example.torchatv2.domain.Identity
import com.example.torchatv2.protocol.SecureSession
import com.example.torchatv2.protocol.SessionState
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class IntegrationTest {

    private val keyGenerator = BouncyCastleKeyPairGenerator()
    private val signatureProvider = BouncyCastleSignatureProvider()
    private val hkdfProvider = BouncyCastleHkdfProvider()
    private val keyAgreement = BouncyCastleKeyAgreementProvider()
    private val aeadProvider = BouncyCastleAeadProvider()

    @Test
    fun testCompleteHandshakeAndDataTransfer() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val bobId = Identity.generate(keyGenerator, signatureProvider)

        val aliceSession = SecureSession(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)
        val bobSession = SecureSession(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)

        val aliceConn = InMemoryTransportConnection()
        val bobConn = InMemoryTransportConnection()
        aliceConn.connectTo(bobConn)

        val latch = CountDownLatch(2) // Wait for both to be established
        val messagesReceivedByAlice = mutableListOf<String>()
        val messagesReceivedByBob = mutableListOf<String>()

        val aliceCoordinator = SessionCoordinator(
            aliceSession, MessageFramer(), aliceConn, true,
            { messagesReceivedByAlice.add(String(it)) },
            { if (it == SessionState.ESTABLISHED) latch.countDown() },
            { fail("Alice error: $it") }
        )

        val bobCoordinator = SessionCoordinator(
            bobSession, MessageFramer(), bobConn, false,
            { messagesReceivedByBob.add(String(it)) },
            { if (it == SessionState.ESTABLISHED) latch.countDown() },
            { fail("Bob error: $it") }
        )

        // 1. Start Handshake
        aliceCoordinator.startHandshake()

        // 2. Wait for Establishment
        assertTrue("Handshake timed out", latch.await(5, TimeUnit.SECONDS))
        assertEquals(SessionState.ESTABLISHED, aliceSession.getState())
        assertEquals(SessionState.ESTABLISHED, bobSession.getState())

        // 3. Send Data
        val msg1 = "Hello Bob from Alice!"
        aliceCoordinator.send(msg1.toByteArray())

        // Wait for Bob to receive msg1 so his ratchet advances and he can reply
        var timeout = 0
        while (messagesReceivedByBob.isEmpty() && timeout < 50) {
            Thread.sleep(100)
            timeout++
        }
        assertTrue("Bob did not receive msg1", messagesReceivedByBob.isNotEmpty())

        val msg2 = "Hi Alice, I got your message!"
        bobCoordinator.send(msg2.toByteArray())

        // Wait a bit for msg2 to reach Alice
        timeout = 0
        while (messagesReceivedByAlice.isEmpty() && timeout < 50) {
            Thread.sleep(100)
            timeout++
        }
        assertTrue("Alice did not receive msg2", messagesReceivedByAlice.isNotEmpty())

        assertEquals(msg1, messagesReceivedByBob[0])
        assertEquals(msg2, messagesReceivedByAlice[0])
    }

    @Test
    fun testFragmentedStreamHandshake() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val bobId = Identity.generate(keyGenerator, signatureProvider)

        val aliceSession = SecureSession(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)
        val bobSession = SecureSession(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)

        val aliceConn = InMemoryTransportConnection()
        val bobConn = InMemoryTransportConnection()
        aliceConn.connectTo(bobConn)

        val latch = CountDownLatch(2)
        val aliceCoordinator = SessionCoordinator(
            aliceSession, MessageFramer(), aliceConn, true,
            {}, { if (it == SessionState.ESTABLISHED) latch.countDown() }, { fail(it.message) }
        )
        val bobCoordinator = SessionCoordinator(
            bobSession, MessageFramer(), bobConn, false,
            {}, { if (it == SessionState.ESTABLISHED) latch.countDown() }, { fail(it.message) }
        )

        // Custom start to use fragmentation
        val m1 = (aliceSession.startInitiator() as com.example.torchatv2.protocol.SessionEvent.HandshakeProduced).data
        aliceConn.sendFragmented(m1, 1) // 1 byte at a time!

        assertTrue("Fragmented handshake timed out", latch.await(10, TimeUnit.SECONDS))
        assertEquals(SessionState.ESTABLISHED, aliceSession.getState())
        assertEquals(SessionState.ESTABLISHED, bobSession.getState())
    }

    @Test
    fun testFailedSessionTermination() {
        val aliceId = Identity.generate(keyGenerator, signatureProvider)
        val bobId = Identity.generate(keyGenerator, signatureProvider)

        val aliceSession = SecureSession(aliceId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)
        val bobSession = SecureSession(bobId, keyGenerator, signatureProvider, hkdfProvider, keyAgreement, aeadProvider)

        val aliceConn = InMemoryTransportConnection()
        val bobConn = InMemoryTransportConnection()
        aliceConn.connectTo(bobConn)

        val errorLatch = CountDownLatch(1)
        val aliceCoordinator = SessionCoordinator(
            aliceSession, MessageFramer(), aliceConn, true,
            {}, {}, { errorLatch.countDown() }
        )
        val bobCoordinator = SessionCoordinator(
            bobSession, MessageFramer(), bobConn, false,
            {}, {}, {}
        )

        aliceCoordinator.startHandshake()
        
        // Push invalid M1 to Bob
        aliceConn.send(ByteArray(178) { 0xFF.toByte() })
        
        // Give some time for async execution
        Thread.sleep(100)
        
        assertEquals(SessionState.FAILED, bobSession.getState())
    }
}
