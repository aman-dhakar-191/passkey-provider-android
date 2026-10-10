package io.github.amandhakar.cryptolab.core

import java.security.KeyPair
import java.security.PublicKey

/**
 * How two phones agree on a shared secret. Implementations wrap vetted primitives (JCA / Android Keystore);
 * the lab compares approaches, it does not invent ciphers.
 */
interface KeyExchange {
    val name: String

    fun generate(): KeyPair

    /** The public key as sent on the wire (X.509 SubjectPublicKeyInfo). */
    fun encode(publicKey: PublicKey): ByteArray = publicKey.encoded

    /** Parses and validates a peer's public key; throws if it is malformed or on the wrong curve. */
    fun decode(encoded: ByteArray): PublicKey

    fun agree(own: KeyPair, peer: PublicKey): ByteArray

    /** Releases [own] once the handshake is done (e.g. deletes a Keystore entry). */
    fun dispose(own: KeyPair) {}
}

/** Authenticated encryption with associated data. Nonces are 12 bytes; the channel never reuses one per key. */
interface Aead {
    val name: String
    val keySize: Int

    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray

    /** Throws (javax.crypto.AEADBadTagException or similar) if anything was changed. */
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray
}

/**
 * One approach to the secure channel: a key exchange plus an AEAD. [id] goes on the wire, so two phones
 * interoperate when they share it, even if each holds its keys differently (e.g. software vs Keystore).
 */
class CipherSuite(
    val id: String,
    val label: String,
    val kex: KeyExchange,
    val aead: Aead,
) {
    /** Runs a tiny key exchange and encryption to find out whether this device's crypto provider can do it. */
    fun isSupported(): Boolean = supportProblem() == null

    fun supportProblem(): String? = runCatching {
        val a = kex.generate()
        val b = kex.generate()
        try {
            val s1 = kex.agree(a, kex.decode(kex.encode(b.public)))
            val s2 = kex.agree(b, kex.decode(kex.encode(a.public)))
            check(s1.contentEquals(s2)) { "key exchange gave different secrets" }
            val key = ByteArray(aead.keySize) { it.toByte() }
            val nonce = ByteArray(12)
            val sealed = aead.seal(key, nonce, byteArrayOf(1), byteArrayOf(2, 3))
            check(aead.open(key, nonce, byteArrayOf(1), sealed).contentEquals(byteArrayOf(2, 3))) { "AEAD round trip failed" }
        } finally {
            kex.dispose(a)
            kex.dispose(b)
        }
    }.exceptionOrNull()?.let { "${it.javaClass.simpleName}: ${it.message}" }

    override fun toString() = label
}
