package io.github.amandhakar.passkey.webauthn

import java.io.ByteArrayOutputStream

/** Minimal CBOR (RFC 8949) writer: just enough for WebAuthn attestation objects and COSE keys. */
class CborWriter {
    private val out = ByteArrayOutputStream()

    private fun head(major: Int, value: Long) {
        val m = major shl 5
        when {
            value < 24 -> out.write(m or value.toInt())
            value <= 0xFF -> { out.write(m or 24); writeBigEndian(value, 1) }
            value <= 0xFFFF -> { out.write(m or 25); writeBigEndian(value, 2) }
            value <= 0xFFFFFFFFL -> { out.write(m or 26); writeBigEndian(value, 4) }
            else -> { out.write(m or 27); writeBigEndian(value, 8) }
        }
    }

    private fun writeBigEndian(value: Long, bytes: Int) {
        for (i in bytes - 1 downTo 0) out.write((value ushr (8 * i)).toInt() and 0xFF)
    }

    fun int(value: Long) = apply { if (value >= 0) head(0, value) else head(1, -1 - value) }

    fun bytes(value: ByteArray) = apply { head(2, value.size.toLong()); out.write(value, 0, value.size) }

    fun text(value: String) = apply {
        val b = value.toByteArray(Charsets.UTF_8)
        head(3, b.size.toLong())
        out.write(b, 0, b.size)
    }

    fun map(size: Int) = apply { head(5, size.toLong()) }

    fun toByteArray(): ByteArray = out.toByteArray()
}
