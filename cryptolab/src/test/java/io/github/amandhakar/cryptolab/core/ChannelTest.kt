package io.github.amandhakar.cryptolab.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ProtocolException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ChannelTest {
    private val pool = Executors.newCachedThreadPool()

    private fun <T> background(block: () -> T) = pool.submit(Callable { block() })

    @Test
    fun `self-test passes for every software suite`() {
        val lines = mutableListOf<SelfTest.Line>()
        SelfTest.run(Suites.software, payloadBytes = 256 * 1024) { lines += it }
        assertEquals(Suites.software.size * 4, lines.size)
        lines.forEach { assertTrue(it.text, it.ok) }
    }

    @Test
    fun `transfers text, empty and odd-sized payloads`() {
        val suite = Suites.software.first()
        for (payload in listOf("hello".toByteArray(), ByteArray(0), ByteArray(Transfer.CHUNK * 3 + 17) { it.toByte() })) {
            val (a, b) = SelfTest.loopbackPair()
            val (i, r) = SelfTest.openPair(suite, a, b)
            val sink = ByteArrayOutputStream()
            val received = background { Transfer.receive(r, 1L shl 20) { _, _ -> sink } }
            val sent = Transfer.send(i, "x", payload.size.toLong(), ByteArrayInputStream(payload))
            val got = received.get(30, TimeUnit.SECONDS)
            assertArrayEquals(payload, sink.toByteArray())
            assertEquals(sent.sha256, got.sha256)
            i.close()
            r.close()
        }
    }

    @Test
    fun `receiver refuses a payload over its limit`() {
        val suite = Suites.software.first()
        val (a, b) = SelfTest.loopbackPair()
        val (i, r) = SelfTest.openPair(suite, a, b)
        val received = background { runCatching { Transfer.receive(r, 10) { _, _ -> ByteArrayOutputStream() } } }
        runCatching { Transfer.send(i, "big", 11, ByteArrayInputStream(ByteArray(11))) }
        assertTrue(received.get(30, TimeUnit.SECONDS).exceptionOrNull() is ProtocolException)
        i.close()
        r.close()
    }

    @Test
    fun `rejecting the code closes both sides`() {
        val suite = Suites.software.first()
        val (a, b) = SelfTest.loopbackPair()
        val responder = background { Handshake.respond(b, { suite }) }
        val initiator = Handshake.initiate(a, suite)
        val pending = responder.get(30, TimeUnit.SECONDS)
        val initiatorResult = background { runCatching { initiator.confirm(true) } }
        try {
            pending.confirm(false)
            fail("expected SecurityException")
        } catch (_: SecurityException) {
        }
        assertTrue(initiatorResult.get(30, TimeUnit.SECONDS).isFailure)
    }

    @Test
    fun `unsupported suite is reported to the initiator`() {
        val (a, b) = SelfTest.loopbackPair()
        val responder = background { runCatching { Handshake.respond(b, { null }) } }
        try {
            Handshake.initiate(a, Suites.software.first())
            fail("expected ProtocolException")
        } catch (e: ProtocolException) {
            assertTrue(e.message!!.contains("does not support"))
        }
        assertTrue(responder.get(30, TimeUnit.SECONDS).isFailure)
    }

    @Test
    fun `changed reveal fails the commitment check`() {
        val suite = Suites.software.first()
        val (initiatorEnd, relayIn) = SelfTest.loopbackPair()
        val (relayOut, responderEnd) = SelfTest.loopbackPair()
        Attacks.relay(relayIn, relayOut) { direction, index, frame ->
            // Frame 1 toward the responder is the REVEAL; its last byte is part of the nonce.
            if (direction == Attacks.Direction.TO_RESPONDER && index == 1) {
                listOf(frame.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() })
            } else {
                listOf(frame)
            }
        }
        val responder = background { runCatching { Handshake.respond(responderEnd, { suite }) } }
        runCatching { Handshake.initiate(initiatorEnd, suite) }
        assertTrue(responder.get(30, TimeUnit.SECONDS).exceptionOrNull() is SecurityException)
        initiatorEnd.close()
    }

    @Test
    fun `man in the middle gets different codes on each side`() {
        repeat(3) {
            val suite = Suites.software[it]
            val (initiatorEnd, attackerIn) = SelfTest.loopbackPair()
            val (attackerOut, responderEnd) = SelfTest.loopbackPair()
            val attack = Attacks.manInTheMiddle(attackerIn, attackerOut, suite)
            val responder = background { Handshake.respond(responderEnd, { suite }) }
            val initiator = Handshake.initiate(initiatorEnd, suite)
            val pending = responder.get(30, TimeUnit.SECONDS)
            val seen = attack.get(30, TimeUnit.SECONDS)
            assertEquals(initiator.sas, seen.codeSeenByInitiator)
            assertEquals(pending.sas, seen.codeSeenByResponder)
            assertNotEquals(initiator.sas, pending.sas)
            assertNotEquals(initiator.sessionId, pending.sessionId)
        }
    }

    @Test
    fun `oversized frame is refused before reading it`() {
        val (a, b) = SelfTest.loopbackPair()
        java.io.DataOutputStream(a.output).run {
            writeInt(Framer.DEFAULT_MAX_FRAME + 1)
            flush()
        }
        try {
            Framer(b).read()
            fail("expected ProtocolException")
        } catch (_: ProtocolException) {
        }
        a.close()
        b.close()
    }
}
