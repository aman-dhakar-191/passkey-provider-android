package io.github.amandhakar.cryptolab.core

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future

/**
 * Simulated attackers sitting between two phones, used by the self-test and the unit tests to show that
 * the channel notices them.
 */
object Attacks {
    private val pool = Executors.newCachedThreadPool { r -> Thread(r, "cryptolab-attack").apply { isDaemon = true } }

    /** Direction of a frame passing through a relay. */
    enum class Direction { TO_RESPONDER, TO_INITIATOR }

    /**
     * Forwards whole frames between [initiator] and [responder]. [tamper] sees each frame with its direction
     * and index (counted per direction, handshake messages included) and returns the frames to forward:
     * the frame itself, a changed copy, nothing (drop) or several (replay).
     */
    fun relay(
        initiator: Connection,
        responder: Connection,
        tamper: (Direction, Int, ByteArray) -> List<ByteArray>,
    ): List<Future<*>> {
        fun pump(from: Connection, to: Connection, direction: Direction) = pool.submit {
            val inFramer = Framer(from)
            val outFramer = Framer(to)
            var index = 0
            try {
                while (true) {
                    val frame = inFramer.read()
                    tamper(direction, index++, frame).forEach { outFramer.write(it) }
                }
            } catch (_: Exception) {
                runCatching { from.close() }
                runCatching { to.close() }
            }
        }
        return listOf(
            pump(initiator, responder, Direction.TO_RESPONDER),
            pump(responder, initiator, Direction.TO_INITIATOR),
        )
    }

    class MitmResult(val codeSeenByInitiator: String, val codeSeenByResponder: String)

    /**
     * A full man in the middle: it answers the initiator as if it were the responder and connects to the
     * responder as if it were the initiator, with its own keys on each side. It can read everything, but
     * only if the two people don't compare codes: the codes it causes differ (except with 1-in-a-million luck).
     */
    fun manInTheMiddle(initiatorSide: Connection, responderSide: Connection, suite: CipherSuite): Future<MitmResult> =
        pool.submit(
            Callable {
                val towardResponder = pool.submit(Callable { Handshake.initiate(responderSide, suite) })
                val towardInitiator = Handshake.respond(initiatorSide, { if (it == suite.id) suite else null })
                val other = towardResponder.get()
                towardInitiator.close()
                other.close()
                MitmResult(codeSeenByInitiator = towardInitiator.sas, codeSeenByResponder = other.sas)
            },
        )
}
