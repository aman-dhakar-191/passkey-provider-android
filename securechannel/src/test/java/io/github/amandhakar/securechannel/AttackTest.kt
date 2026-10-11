package io.github.amandhakar.securechannel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ProtocolException
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * What an attacker near the phones can and can't do to a QR-code session (the way Passkey Vault moves
 * passkeys): eavesdrop, connect first without the QR code, hold a connection open, or flood the receiver.
 */
class AttackTest {
    private val pool = Executors.newCachedThreadPool()
    private val suite = Suites.software.first()
    private val suiteFor: (String) -> CipherSuite? = { id -> Suites.software.firstOrNull { it.id == id } }

    private fun secret() = ByteArray(Handshake.QR_SECRET_SIZE).also { SecureRandom().nextBytes(it) }

    /** The real old phone: connects with the QR secret and sends [payload]. */
    private fun sender(port: Int, secret: ByteArray, payload: ByteArray) = pool.submit(Callable {
        val channel = Handshake.initiate(TcpTransport.connect("127.0.0.1", port), suite, secret).confirm(true)
        Transfer.send(channel, "passkeys.json", payload.size.toLong(), ByteArrayInputStream(payload))
        Transfer.finish(channel)
        channel.close()
    })

    private fun receiveOne(channel: SecureChannel): ByteArray {
        val sink = ByteArrayOutputStream()
        Transfer.receiveAll(channel, 1L shl 20, { _, _ -> sink }, maxItems = 1) {}
        channel.close()
        return sink.toByteArray()
    }

    @Test
    fun `an eavesdropper sees neither the payload nor the QR secret`() {
        val secret = secret()
        val payload = "PRIVATE-KEY-MATERIAL-".repeat(50).toByteArray()
        val captured = Collections.synchronizedList(mutableListOf<ByteArray>())
        val (senderEnd, relayIn) = SelfTest.loopbackPair()
        val (relayOut, receiverEnd) = SelfTest.loopbackPair()
        Attacks.relay(relayIn, relayOut) { _, _, frame -> captured += frame; listOf(frame) }

        val received = pool.submit(Callable {
            receiveOne(Handshake.respond(receiverEnd, suiteFor, secret).confirm(true))
        })
        val channel = Handshake.initiate(senderEnd, suite, secret).confirm(true)
        Transfer.send(channel, "passkeys.json", payload.size.toLong(), ByteArrayInputStream(payload))
        Transfer.finish(channel)
        assertArrayEquals(payload, received.get(30, TimeUnit.SECONDS))

        val wire = captured.fold(ByteArray(0)) { acc, frame -> acc + frame }
        assertFalse("plaintext on the wire", contains(wire, "PRIVATE-KEY-MATERIAL-".toByteArray()))
        assertFalse("QR secret on the wire", contains(wire, secret))
        assertFalse("part of the QR secret on the wire", contains(wire, secret.copyOf(8)))
    }

    @Test
    fun `a stranger connecting first is dropped and the real phone still gets through`() {
        val secret = secret()
        val payload = "the real passkeys".toByteArray()
        TcpTransport.TcpListener(port = 0).use { listener ->
            val rejected = Collections.synchronizedList(mutableListOf<Exception>())
            val receiver = pool.submit(Callable {
                QrReceiver.accept(listener, suiteFor, secret, handshakeTimeoutMs = 5_000) { _, e -> rejected += e }
            })
            // 1. Someone on the network without the QR code (guessing a secret).
            val stranger = runCatching {
                Handshake.initiate(TcpTransport.connect("127.0.0.1", listener.port), suite, secret()).confirm(true)
            }
            assertTrue("a wrong secret must not get a channel", stranger.isFailure)
            // 2. Someone who doesn't use a QR code at all (would need people to compare codes).
            val noQr = runCatching {
                Handshake.initiate(TcpTransport.connect("127.0.0.1", listener.port), suite).confirm(true)
            }
            assertTrue(noQr.isFailure)
            // 3. The real old phone.
            val sent = sender(listener.port, secret, payload)
            assertArrayEquals(payload, receiveOne(receiver.get(30, TimeUnit.SECONDS)))
            sent.get(30, TimeUnit.SECONDS)
            assertEquals(2, rejected.size)
        }
    }

    @Test
    fun `a connection that never speaks only holds the receiver until the handshake timeout`() {
        val secret = secret()
        TcpTransport.TcpListener(port = 0).use { listener ->
            val receiver = pool.submit(Callable { QrReceiver.accept(listener, suiteFor, secret, handshakeTimeoutMs = 500) })
            val silent = TcpTransport.connect("127.0.0.1", listener.port) // connects, sends nothing
            val started = System.nanoTime()
            val sent = sender(listener.port, secret, "hi".toByteArray())
            assertArrayEquals("hi".toByteArray(), receiveOne(receiver.get(30, TimeUnit.SECONDS)))
            sent.get(30, TimeUnit.SECONDS)
            assertTrue("waited too long", (System.nanoTime() - started) / 1_000_000 < 10_000)
            silent.close()
        }
    }

    @Test
    fun `the receiver gives up after too many strangers instead of listening forever`() {
        TcpTransport.TcpListener(port = 0).use { listener ->
            val receiver = pool.submit(Callable { runCatching { QrReceiver.accept(listener, suiteFor, secret(), maxAttempts = 3) } })
            repeat(3) {
                runCatching { Handshake.initiate(TcpTransport.connect("127.0.0.1", listener.port), suite, secret()).confirm(true) }
            }
            val result = receiver.get(30, TimeUnit.SECONDS)
            assertTrue(result.exceptionOrNull() is SecurityException)
        }
    }

    @Test
    fun `a sender can't push more items than the receiver allows`() {
        val secret = secret()
        val (a, b) = SelfTest.loopbackPair()
        val received = pool.submit(Callable {
            try {
                runCatching { Transfer.receiveAll(Handshake.respond(b, suiteFor, secret).confirm(true), 1024, { _, _ -> ByteArrayOutputStream() }, maxItems = 1) {} }
            } finally {
                b.close() // so the sender's wait for an answer ends
            }
        })
        val channel = Handshake.initiate(a, suite, secret).confirm(true)
        runCatching {
            repeat(3) { Transfer.send(channel, "x", 1, ByteArrayInputStream(byteArrayOf(1))) }
        }
        assertTrue(received.get(30, TimeUnit.SECONDS).exceptionOrNull() is ProtocolException)
    }

    @Test
    fun `a captured session can't be replayed to a new receiver`() {
        // Record everything the real sender sends, then play it to a receiver with the same QR code.
        val secret = secret()
        val toReceiver = Collections.synchronizedList(mutableListOf<ByteArray>())
        val (senderEnd, relayIn) = SelfTest.loopbackPair()
        val (relayOut, receiverEnd) = SelfTest.loopbackPair()
        Attacks.relay(relayIn, relayOut) { direction, _, frame ->
            if (direction == Attacks.Direction.TO_RESPONDER) toReceiver += frame
            listOf(frame)
        }
        val first = pool.submit(Callable { receiveOne(Handshake.respond(receiverEnd, suiteFor, secret).confirm(true)) })
        val channel = Handshake.initiate(senderEnd, suite, secret).confirm(true)
        Transfer.send(channel, "p", 3, ByteArrayInputStream(byteArrayOf(1, 2, 3)))
        Transfer.finish(channel)
        first.get(30, TimeUnit.SECONDS)

        // Replay: the receiver picks a fresh key and nonce, so the old REVEAL and records don't fit.
        val (attacker, victim) = SelfTest.loopbackPair()
        val replayed = pool.submit(Callable { runCatching { receiveOne(Handshake.respond(victim, suiteFor, secret).confirm(true)) } })
        val framer = Framer(attacker)
        runCatching {
            framer.write(toReceiver[0]) // COMMIT
            framer.read() // receiver's fresh HELLO
            toReceiver.drop(1).forEach { framer.write(it) }
        }
        val outcome = replayed.get(30, TimeUnit.SECONDS)
        assertTrue("replayed session accepted", outcome.isFailure)
        attacker.close()
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    @Test
    fun `checks itself`() {
        assertTrue(contains(byteArrayOf(1, 2, 3, 4), byteArrayOf(2, 3)))
        assertFalse(contains(byteArrayOf(1, 2, 3, 4), byteArrayOf(3, 2)))
        try {
            QrReceiver.accept(object : Listener {
                override fun accept(): Connection = throw java.io.IOException("closed")
                override fun close() {}
            }, suiteFor, secret())
            fail("expected the closed listener to stop it")
        } catch (_: java.io.IOException) {
        }
    }
}
