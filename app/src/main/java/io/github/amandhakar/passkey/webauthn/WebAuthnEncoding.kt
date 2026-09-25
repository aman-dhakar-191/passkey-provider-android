package io.github.amandhakar.passkey.webauthn

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Pure byte-level WebAuthn encoding (no Android dependencies, unit-tested). */
object WebAuthnEncoding {
    const val FLAG_USER_PRESENT = 0x01
    const val FLAG_USER_VERIFIED = 0x04
    const val FLAG_ATTESTED_DATA = 0x40
    const val COSE_ALG_ES256 = -7

    /** Identifies this authenticator model. Sent with "none" attestation; not a per-device identifier. */
    val AAGUID: ByteArray = UUID.fromString("34a0a0cc-2dc3-4d1c-913e-a7bdea7a92d1").let {
        ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array()
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** COSE_Key for an EC2 P-256 public key (RFC 9053), keys in CTAP2 canonical order. */
    fun coseEs256PublicKey(x: ByteArray, y: ByteArray): ByteArray {
        require(x.size == 32 && y.size == 32) { "P-256 coordinates must be 32 bytes" }
        return CborWriter().map(5)
            .int(1).int(2) // kty: EC2
            .int(3).int(COSE_ALG_ES256.toLong()) // alg: ES256
            .int(-1).int(1) // crv: P-256
            .int(-2).bytes(x)
            .int(-3).bytes(y)
            .toByteArray()
    }

    fun attestedCredentialData(credentialId: ByteArray, cosePublicKey: ByteArray): ByteArray {
        require(credentialId.size <= 1023) { "credential id too long" }
        return ByteBuffer.allocate(16 + 2 + credentialId.size + cosePublicKey.size)
            .put(AAGUID)
            .putShort(credentialId.size.toShort())
            .put(credentialId)
            .put(cosePublicKey)
            .array()
    }

    fun authenticatorData(
        rpId: String,
        flags: Int,
        signCount: Long,
        attestedCredentialData: ByteArray? = null,
    ): ByteArray {
        val attested = attestedCredentialData ?: ByteArray(0)
        val finalFlags = if (attestedCredentialData != null) flags or FLAG_ATTESTED_DATA else flags
        return ByteBuffer.allocate(32 + 1 + 4 + attested.size)
            .put(sha256(rpId.toByteArray(Charsets.UTF_8)))
            .put(finalFlags.toByte())
            .putInt(signCount.toInt())
            .put(attested)
            .array()
    }

    /** Attestation object with the "none" format. Keys are in CTAP2 canonical order. */
    fun noneAttestationObject(authenticatorData: ByteArray): ByteArray =
        CborWriter().map(3)
            .text("fmt").text("none")
            .text("attStmt").map(0)
            .text("authData").bytes(authenticatorData)
            .toByteArray()

    /** Big-endian unsigned, left-padded to [length] bytes (BigInteger adds a sign byte / drops zeros). */
    fun unsignedFixed(value: BigInteger, length: Int = 32): ByteArray {
        val raw = value.toByteArray()
        val trimmed = if (raw.size > length) raw.copyOfRange(raw.size - length, raw.size) else raw
        return ByteArray(length - trimmed.size) + trimmed
    }

    /** clientDataJSON per WebAuthn §5.8.1. Fields are serialised in the order the spec's algorithm uses. */
    fun clientDataJson(type: String, challenge: ByteArray, origin: String): ByteArray =
        ("{\"type\":${jsonString(type)},\"challenge\":${jsonString(Base64Url.encode(challenge))}," +
            "\"origin\":${jsonString(origin)},\"crossOrigin\":false}").toByteArray(Charsets.UTF_8)

    private fun jsonString(s: String): String = buildString {
        append('"')
        for (c in s) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c < ' ' -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }
}
