package io.github.amandhakar.cryptolab.core

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ProtocolException
import java.nio.ByteBuffer
import java.security.MessageDigest

/** A duplex byte stream between two phones. Transports (TCP, Bluetooth, ...) provide one. */
interface Connection : Closeable {
    val input: InputStream
    val output: OutputStream

    /** Who is on the other end, for the log. */
    val peer: String
}

/** Waits for phones to connect. Each transport (TCP, Bluetooth, ...) provides one. */
interface Listener : Closeable {
    /** Blocks until a phone connects; [close] from another thread to stop waiting. */
    fun accept(): Connection
}

/** Length-prefixed frames over a [Connection]. A frame larger than [maxFrame] is refused before it is read. */
class Framer(connection: Connection, private val maxFrame: Int = DEFAULT_MAX_FRAME) {
    private val input = DataInputStream(connection.input)
    private val output = DataOutputStream(connection.output)

    fun write(frame: ByteArray) {
        output.writeInt(frame.size)
        output.write(frame)
        output.flush()
    }

    fun read(): ByteArray {
        val size = input.readInt()
        if (size < 0 || size > maxFrame) throw ProtocolException("Frame of $size bytes refused (limit $maxFrame)")
        return ByteArray(size).also { input.readFully(it) }
    }

    companion object {
        const val DEFAULT_MAX_FRAME = 256 * 1024
    }
}

/** Builds a message from fields; variable-length fields are prefixed with their length. */
class WireWriter {
    private val out = ByteArrayOutputStream()

    fun raw(bytes: ByteArray) = apply { out.write(bytes) }
    fun u8(value: Int) = apply { out.write(value) }
    fun u64(value: Long) = apply { out.write(ByteBuffer.allocate(8).putLong(value).array()) }
    fun bytes(value: ByteArray) = apply {
        require(value.size <= 0xFFFF) { "field too long" }
        out.write(value.size ushr 8)
        out.write(value.size and 0xFF)
        out.write(value)
    }
    fun string(value: String) = bytes(value.toByteArray(Charsets.UTF_8))
    fun build(): ByteArray = out.toByteArray()
}

/** Reads fields written by [WireWriter], refusing truncated or over-long messages. */
class WireReader(private val data: ByteArray) {
    private var pos = 0

    private fun take(n: Int): ByteArray {
        if (n < 0 || pos + n > data.size) throw ProtocolException("Truncated message")
        return data.copyOfRange(pos, pos + n).also { pos += n }
    }

    fun raw(n: Int) = take(n)
    fun u8(): Int = take(1)[0].toInt() and 0xFF
    fun u64(): Long = ByteBuffer.wrap(take(8)).long
    fun bytes(): ByteArray {
        val len = (u8() shl 8) or u8()
        return take(len)
    }
    fun string(): String = String(bytes(), Charsets.UTF_8)
    fun end() {
        if (pos != data.size) throw ProtocolException("${data.size - pos} unexpected trailing bytes")
    }
}

internal fun sha256(vararg parts: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").run {
        parts.forEach { update(it) }
        digest()
    }

internal fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
