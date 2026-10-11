package io.github.amandhakar.securechannel

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The receiving side of a QR-code session: waits until a phone that knows the QR code's secret connects.
 *
 * Anyone on the same network can connect to the listening port. Such a connection can't get through the
 * handshake (it would need the secret), but if the receiver gave up after one failed connection, or waited on
 * one that never speaks, anybody nearby could stop the transfer. So failed or silent connections are dropped
 * (each gets [handshakeTimeoutMs]) and the receiver keeps listening, up to [maxAttempts] connections.
 */
object QrReceiver {
    private val watchdogs = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "securechannel-handshake-watchdog").apply { isDaemon = true }
    }

    /**
     * Returns the open, key-confirmed channel to the first phone that used [qrSecret]. [onRejected] hears about
     * each connection that didn't. Throws if [listener] is closed, or after [maxAttempts] failed connections.
     */
    fun accept(
        listener: Listener,
        suiteFor: (String) -> CipherSuite?,
        qrSecret: ByteArray,
        handshakeTimeoutMs: Long = 15_000,
        maxAttempts: Int = 20,
        onRejected: (peer: String, reason: Exception) -> Unit = { _, _ -> },
    ): SecureChannel {
        repeat(maxAttempts) {
            val connection = listener.accept()
            // Closing the socket is the only way to interrupt a blocked read on it.
            val watchdog = watchdogs.schedule({ runCatching { connection.close() } }, handshakeTimeoutMs, TimeUnit.MILLISECONDS)
            try {
                val pending = Handshake.respond(connection, suiteFor, qrSecret)
                if (!pending.usesQrSecret) {
                    pending.close()
                    throw SecurityException("It didn't use this QR code")
                }
                val channel = pending.confirm(true)
                // If the watchdog already fired, the connection is closed: treat it as a failed attempt.
                if (!watchdog.cancel(false)) throw SecurityException("The handshake took too long")
                return channel
            } catch (e: Exception) {
                watchdog.cancel(false)
                runCatching { connection.close() }
                onRejected(connection.peer, e)
            }
        }
        throw SecurityException("Stopped after $maxAttempts connections that didn't have this QR code")
    }
}
