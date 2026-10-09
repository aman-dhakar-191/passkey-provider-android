package io.github.amandhakar.cryptolab.core

import java.io.InputStream
import java.io.OutputStream
import java.net.ProtocolException
import java.security.MessageDigest

/**
 * Sends one payload (a file or text) over an open [SecureChannel]:
 * START(name, size), DATA chunks, END(SHA-256), then the receiver answers ACK(status, SHA-256).
 * The AEAD already protects every chunk; the end-to-end hash also proves nothing went missing at the end.
 */
object Transfer {
    const val CHUNK = 32 * 1024
    private const val ACK_OK = 0
    private const val ACK_BAD = 1

    class Result(val name: String, val bytes: Long, val sha256: String, val millis: Long) {
        val megabytesPerSecond: Double get() = if (millis <= 0) 0.0 else bytes / 1_048_576.0 / (millis / 1000.0)
    }

    fun send(channel: SecureChannel, name: String, size: Long, input: InputStream): Result {
        val started = System.nanoTime()
        val digest = MessageDigest.getInstance("SHA-256")
        channel.send(RecordType.START, WireWriter().string(name).u64(size).build())
        val buf = ByteArray(CHUNK)
        var sent = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (n == 0) continue
            digest.update(buf, 0, n)
            channel.send(RecordType.DATA, buf.copyOf(n))
            sent += n
        }
        if (sent != size) throw ProtocolException("Read $sent bytes but announced $size")
        val hash = digest.digest()
        channel.send(RecordType.END, hash)

        val ack = channel.receive()
        if (ack.type != RecordType.ACK) throw ProtocolException("Expected ACK, got record ${ack.type}")
        val r = WireReader(ack.payload)
        val status = r.u8()
        val theirHash = r.bytes()
        r.end()
        if (status != ACK_OK || !MessageDigest.isEqual(hash, theirHash)) {
            throw SecurityException("The other phone received different data (hash mismatch)")
        }
        return Result(name, sent, hash.hex(), (System.nanoTime() - started) / 1_000_000)
    }

    /**
     * Receives one payload. [open] gets the announced name and size and returns where to write it.
     * Payloads over [maxBytes] are refused before anything is written.
     */
    fun receive(channel: SecureChannel, maxBytes: Long, open: (name: String, size: Long) -> OutputStream): Result {
        val start = channel.receive()
        if (start.type != RecordType.START) throw ProtocolException("Expected START, got record ${start.type}")
        val r = WireReader(start.payload)
        val name = r.string()
        val size = r.u64()
        r.end()
        if (size < 0 || size > maxBytes) throw ProtocolException("Payload of $size bytes refused (limit $maxBytes)")

        val started = System.nanoTime()
        val digest = MessageDigest.getInstance("SHA-256")
        var received = 0L
        var hash: ByteArray? = null
        open(name, size).use { out ->
            while (hash == null) {
                val record = channel.receive()
                when (record.type) {
                    RecordType.DATA -> {
                        received += record.payload.size
                        if (received > size) throw ProtocolException("More data than announced")
                        digest.update(record.payload)
                        out.write(record.payload)
                    }
                    RecordType.END -> {
                        val ours = digest.digest()
                        val ok = received == size && MessageDigest.isEqual(ours, record.payload)
                        channel.send(RecordType.ACK, WireWriter().u8(if (ok) ACK_OK else ACK_BAD).bytes(ours).build())
                        if (!ok) throw SecurityException("Received data does not match the sender's hash")
                        hash = ours
                    }
                    else -> throw ProtocolException("Unexpected record ${record.type} during transfer")
                }
            }
        }
        return Result(name, received, hash!!.hex(), (System.nanoTime() - started) / 1_000_000)
    }
}
