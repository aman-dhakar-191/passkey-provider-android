package io.github.amandhakar.passkey.transfer

import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypts a movable passkey's private key for storage on this phone: a fresh AES-256-GCM key encrypts it,
 * and the vault's RSA public key (RSA-OAEP) encrypts that AES key. Wrapping needs only the public key, so
 * creating a passkey needs no extra prompt; unwrapping needs the vault's private key in the Keystore, which
 * only works shortly after a fingerprint or screen-lock check.
 *
 * Format: version (1) | RSA ciphertext length (2) | RSA ciphertext | GCM IV (12) | GCM ciphertext and tag.
 * The credential id is the associated data, so a wrapped key can't be swapped onto another passkey.
 */
internal object KeyWrap {
    private const val VERSION = 1
    private const val IV_SIZE = 12

    /** The Keystore supports SHA-256 OAEP with MGF1 SHA-1, so both sides use exactly that. */
    const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    fun wrap(vaultPublicKey: PublicKey, secret: ByteArray, associatedData: ByteArray, random: SecureRandom = SecureRandom()): ByteArray {
        val contentKey = ByteArray(32).also { random.nextBytes(it) }
        val iv = ByteArray(IV_SIZE).also { random.nextBytes(it) }
        try {
            val wrappedKey = Cipher.getInstance(RSA_TRANSFORMATION).run {
                init(Cipher.ENCRYPT_MODE, vaultPublicKey, OAEP)
                doFinal(contentKey)
            }
            val sealed = aes(Cipher.ENCRYPT_MODE, contentKey, iv, associatedData).doFinal(secret)
            return ByteBuffer.allocate(1 + 2 + wrappedKey.size + IV_SIZE + sealed.size)
                .put(VERSION.toByte())
                .putShort(wrappedKey.size.toShort())
                .put(wrappedKey)
                .put(iv)
                .put(sealed)
                .array()
        } finally {
            contentKey.fill(0)
        }
    }

    /** [rsaDecrypt] decrypts the RSA part with the vault's private key (a Keystore cipher on the phone). */
    fun unwrap(blob: ByteArray, associatedData: ByteArray, rsaDecrypt: (ByteArray) -> ByteArray): ByteArray {
        val buf = ByteBuffer.wrap(blob)
        require(blob.size > 3 && buf.get().toInt() == VERSION) { "Unknown wrapped key format" }
        val rsaSize = buf.short.toInt() and 0xFFFF
        require(buf.remaining() > rsaSize + IV_SIZE) { "Wrapped key is truncated" }
        val wrappedKey = ByteArray(rsaSize).also { buf.get(it) }
        val iv = ByteArray(IV_SIZE).also { buf.get(it) }
        val sealed = ByteArray(buf.remaining()).also { buf.get(it) }
        val contentKey = rsaDecrypt(wrappedKey)
        try {
            return aes(Cipher.DECRYPT_MODE, contentKey, iv, associatedData).doFinal(sealed)
        } finally {
            contentKey.fill(0)
        }
    }

    private fun aes(mode: Int, key: ByteArray, iv: ByteArray, associatedData: ByteArray) =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            updateAAD(associatedData)
        }
}
