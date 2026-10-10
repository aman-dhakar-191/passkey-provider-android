package io.github.amandhakar.cryptolab.core

import io.github.amandhakar.cryptolab.transport.TcpTransport
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Runs every suite on one device over loopback TCP (real sockets, both ends in this process):
 * handshake, transfer, and the attacks the channel must notice. Needs no second phone.
 */
object SelfTest {
    class Line(val ok: Boolean, val text: String)

    private val pool = Executors.newCachedThreadPool { r -> Thread(r, "cryptolab-selftest").apply { isDaemon = true } }
    private const val TIMEOUT_S = 60L

    fun run(suites: List<CipherSuite>, payloadBytes: Int = 1 shl 20, log: (Line) -> Unit) {
        for (suite in suites) {
            val problem = suite.supportProblem()
            if (problem != null) {
                log(Line(false, "${suite.label}: not supported on this device ($problem)"))
                continue
            }
            step(log, suite, "transfer") { transfer(suite, payloadBytes) }
            step(log, suite, "tampered record") { tamperedRecordIsRefused(suite) }
            step(log, suite, "replayed record") { replayedRecordIsRefused(suite) }
            step(log, suite, "man in the middle") { manInTheMiddleChangesCodes(suite) }
            step(log, suite, "QR secret") { qrSecretAuthenticates(suite) }
        }
    }

    private fun step(log: (Line) -> Unit, suite: CipherSuite, name: String, block: () -> String) {
        val line = try {
            Line(true, "${suite.label} · $name: ${block()}")
        } catch (e: Throwable) {
            Line(false, "${suite.label} · $name FAILED: ${e.javaClass.simpleName}: ${e.message}")
        }
        log(line)
    }

    /** A connected pair of loopback TCP connections. */
    fun loopbackPair(): Pair<Connection, Connection> =
        TcpTransport.TcpListener(port = 0).use { listener ->
            val accepted = pool.submit(Callable { listener.accept() })
            val client = TcpTransport.connect("127.0.0.1", listener.port)
            client to accepted.get(TIMEOUT_S, TimeUnit.SECONDS)
        }

    /** Handshakes both ends (each confirming the code), returning (initiator, responder) channels. */
    fun openPair(suite: CipherSuite, initiatorSide: Connection, responderSide: Connection): Pair<SecureChannel, SecureChannel> {
        val responder = pool.submit(Callable { Handshake.respond(responderSide, { if (it == suite.id) suite else null }) })
        val initiator = Handshake.initiate(initiatorSide, suite)
        val pendingResponder = responder.get(TIMEOUT_S, TimeUnit.SECONDS)
        check(initiator.sas == pendingResponder.sas) { "codes differ without an attacker: ${initiator.sas} vs ${pendingResponder.sas}" }
        val confirmedResponder = pool.submit(Callable { pendingResponder.confirm(true) })
        val i = initiator.confirm(true)
        return i to confirmedResponder.get(TIMEOUT_S, TimeUnit.SECONDS)
    }

    private fun transfer(suite: CipherSuite, payloadBytes: Int): String {
        val payload = ByteArray(payloadBytes).also { SecureRandom().nextBytes(it) }
        val (a, b) = loopbackPair()
        val started = System.nanoTime()
        val (i, r) = openPair(suite, a, b)
        val handshakeMs = (System.nanoTime() - started) / 1_000_000
        try {
            val sink = ByteArrayOutputStream()
            val received = pool.submit(Callable { Transfer.receive(r, payloadBytes.toLong()) { _, _ -> sink } })
            val sent = Transfer.send(i, "selftest.bin", payloadBytes.toLong(), ByteArrayInputStream(payload))
            received.get(TIMEOUT_S, TimeUnit.SECONDS)
            check(sink.toByteArray().contentEquals(payload)) { "received bytes differ" }
            return "handshake $handshakeMs ms, ${payloadBytes / 1024} KiB in ${sent.millis} ms " +
                "(%.1f MB/s), hashes match".format(sent.megabytesPerSecond)
        } finally {
            i.close()
            r.close()
        }
    }

    /** Flips one bit in the first record after the handshake (frames 0 and 1 toward the responder are COMMIT and REVEAL). */
    private fun tamperedRecordIsRefused(suite: CipherSuite): String =
        expectRefusal(suite) { direction, index, frame ->
            if (direction == Attacks.Direction.TO_RESPONDER && index == 2) {
                listOf(frame.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() })
            } else {
                listOf(frame)
            }
        }

    /** Sends the initiator's first record twice. */
    private fun replayedRecordIsRefused(suite: CipherSuite): String =
        expectRefusal(suite) { direction, index, frame ->
            if (direction == Attacks.Direction.TO_RESPONDER && index == 2) listOf(frame, frame) else listOf(frame)
        }

    /**
     * Initiator -> relay -> responder. The handshake passes untouched; the relay meddles with the first
     * record (the initiator's CONFIRM). The responder must refuse it.
     */
    private fun expectRefusal(suite: CipherSuite, tamper: (Attacks.Direction, Int, ByteArray) -> List<ByteArray>): String {
        val (initiatorEnd, relayFromInitiator) = loopbackPair()
        val (relayToResponder, responderEnd) = loopbackPair()
        Attacks.relay(relayFromInitiator, relayToResponder, tamper)
        val responder = pool.submit(Callable {
            val pending = Handshake.respond(responderEnd, { if (it == suite.id) suite else null })
            // Read one record past the confirmation so a replayed copy of it is caught too.
            runCatching { pending.confirm(true).receive() }.exceptionOrNull()
        })
        val pending = Handshake.initiate(initiatorEnd, suite)
        val initiatorResult = pool.submit(Callable { runCatching { pending.confirm(true) } })
        val refusal = responder.get(TIMEOUT_S, TimeUnit.SECONDS)
        initiatorResult.get(TIMEOUT_S, TimeUnit.SECONDS)
        initiatorEnd.close()
        responderEnd.close()
        if (refusal is SecurityException) return "refused (${refusal.message})"
        throw IllegalStateException("not refused: ${refusal?.let { "${it.javaClass.simpleName}: ${it.message}" } ?: "accepted"}")
    }

    /**
     * QR mode: with the same secret both sides confirm without comparing codes; with a different one (an old QR
     * code, or an attacker who never saw it) the key confirmation fails on both sides.
     */
    private fun qrSecretAuthenticates(suite: CipherSuite): String {
        fun attempt(senderSecret: ByteArray, receiverSecret: ByteArray): Pair<Throwable?, Throwable?> {
            val (a, b) = loopbackPair()
            val responder = pool.submit(Callable {
                runCatching { Handshake.respond(b, { if (it == suite.id) suite else null }, receiverSecret).confirm(true) }
            })
            val initiator = runCatching { Handshake.initiate(a, suite, senderSecret).confirm(true) }
            val responded = responder.get(TIMEOUT_S, TimeUnit.SECONDS)
            initiator.getOrNull()?.close()
            responded.getOrNull()?.close()
            a.close()
            b.close()
            return initiator.exceptionOrNull() to responded.exceptionOrNull()
        }
        val random = SecureRandom()
        val secret = ByteArray(Handshake.QR_SECRET_SIZE).also { random.nextBytes(it) }
        val good = attempt(secret, secret)
        check(good.first == null && good.second == null) { "matching secrets failed: ${good.first ?: good.second}" }
        val other = ByteArray(Handshake.QR_SECRET_SIZE).also { random.nextBytes(it) }
        val bad = attempt(secret, other)
        check(bad.first != null && bad.second != null) { "a wrong secret was accepted" }
        return "matching secret connects without a code; a wrong secret is refused on both sides"
    }

    private fun manInTheMiddleChangesCodes(suite: CipherSuite): String {
        val (initiatorEnd, attackerFromInitiator) = loopbackPair()
        val (attackerToResponder, responderEnd) = loopbackPair()
        val attack = Attacks.manInTheMiddle(attackerFromInitiator, attackerToResponder, suite)
        val responder = pool.submit(Callable { Handshake.respond(responderEnd, { if (it == suite.id) suite else null }) })
        val initiator = Handshake.initiate(initiatorEnd, suite)
        val pendingResponder = responder.get(TIMEOUT_S, TimeUnit.SECONDS)
        attack.get(TIMEOUT_S, TimeUnit.SECONDS)
        initiator.close()
        pendingResponder.close()
        check(initiator.sas != pendingResponder.sas) { "codes matched despite the attacker (1 in a million, run again)" }
        return "codes differ (${initiator.sas} vs ${pendingResponder.sas}), so comparing them exposes the attacker"
    }
}
