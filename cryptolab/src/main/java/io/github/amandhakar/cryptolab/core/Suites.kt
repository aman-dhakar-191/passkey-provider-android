package io.github.amandhakar.cryptolab.core

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** The software suites (plain JCA, so they run on the JVM in unit tests and on any Android 14+ phone). */
object Suites {
    const val X25519_AESGCM = "x25519-hkdf256-aes256gcm"
    const val X25519_CHACHA = "x25519-hkdf256-chacha20poly1305"
    const val P256_AESGCM = "p256-hkdf256-aes256gcm"

    val software: List<CipherSuite> = listOf(
        CipherSuite(X25519_AESGCM, "X25519 + AES-256-GCM", X25519, AesGcm),
        CipherSuite(X25519_CHACHA, "X25519 + ChaCha20-Poly1305", X25519, ChaCha20Poly1305),
        CipherSuite(P256_AESGCM, "P-256 + AES-256-GCM", P256, AesGcm),
    )
}

/** Tries provider algorithm names in order: the JDK and Android's Conscrypt don't always use the same ones. */
internal fun <T> firstAvailable(names: List<String>, get: (String) -> T): T {
    var last: Exception? = null
    for (name in names) {
        try {
            return get(name)
        } catch (e: Exception) {
            last = e
        }
    }
    throw last ?: IllegalStateException("no algorithm names")
}

object X25519 : KeyExchange {
    override val name = "X25519"
    private val generatorNames = listOf("X25519", "XDH")
    private val factoryNames = listOf("XDH", "X25519")
    private val agreementNames = listOf("XDH", "X25519")

    override fun generate(): KeyPair = firstAvailable(generatorNames) { KeyPairGenerator.getInstance(it) }.generateKeyPair()

    override fun decode(encoded: ByteArray): PublicKey =
        firstAvailable(factoryNames) { KeyFactory.getInstance(it) }.generatePublic(X509EncodedKeySpec(encoded))

    override fun agree(own: KeyPair, peer: PublicKey): ByteArray {
        val secret = firstAvailable(agreementNames) { KeyAgreement.getInstance(it) }.run {
            init(own.private)
            doPhase(peer, true)
            generateSecret()
        }
        // A low-order peer key gives an all-zero secret (RFC 7748 §6.1): an attacker could force a known key.
        if (secret.all { it == 0.toByte() }) throw SecurityException("Peer sent a low-order X25519 key")
        return secret
    }
}

/** NIST P-256 ECDH. Same curve as passkeys and the Android Keystore, so it also has a hardware variant. */
object P256 : KeyExchange {
    override val name = "P-256"
    private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    override fun generate(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    override fun decode(encoded: ByteArray): PublicKey {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded)) as ECPublicKey
        if (key.params.order != ORDER) throw SecurityException("Peer key is not on P-256")
        return key
    }

    // The providers check that the peer point is on the curve (no invalid-curve attack).
    override fun agree(own: KeyPair, peer: PublicKey): ByteArray = KeyAgreement.getInstance("ECDH").run {
        init(own.private)
        doPhase(peer, true)
        generateSecret()
    }
}

object AesGcm : Aead {
    override val name = "AES-256-GCM"
    override val keySize = 32

    override fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray =
        cipher(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext)

    override fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray =
        cipher(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext)

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray) =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
        }
}

object ChaCha20Poly1305 : Aead {
    override val name = "ChaCha20-Poly1305"
    override val keySize = 32
    // JDK name first, then Android's (Conscrypt).
    private val names = listOf("ChaCha20-Poly1305", "ChaCha20/Poly1305/NoPadding")

    override fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray =
        cipher(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext)

    override fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray =
        cipher(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext)

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray) =
        firstAvailable(names) { Cipher.getInstance(it) }.apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(aad)
        }
}
