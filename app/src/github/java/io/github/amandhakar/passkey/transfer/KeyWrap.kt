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
 * only works shortly after a fingerprint check.
 *
 * Format: version (1) | RSA ciphertext length (2) | RSA ciphertext | GCM IV (12) | GCM ciphertext and tag.
 * The credential id is the associated data, so a wrapped key can't be swapped onto another passkey.
 * The version byte says which vault key wrapped it: [VAULT_V1] (fingerprint or screen lock, app 1.3.8 era)
 * or [VAULT_V2] (fingerprint only, invalidated when fingerprints change).
 */
internal object KeyWrap {
    const val VAULT_V1 = 1
    const val VAULT_V2 = 2
    private const val IV_SIZE = 12

    /** The Keystore supports SHA-256 OAEP with MGF1 SHA-1, so both sides use exactly that. */
    const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    fun wrap(
        vaultPublicKey: PublicKey,
        secret: ByteArray,
        associatedData: ByteArray,
        vault: Int = VAULT_V2,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        require(vault == VAULT_V1 || vault == VAULT_V2) { "Unknown vault $vault" }
        val contentKey = ByteArray(32).also { random.nextBytes(it) }
        val iv = ByteArray(IV_SIZE).also { random.nextBytes(it) }
        try {
            val wrappedKey = Cipher.getInstance(RSA_TRANSFORMATION).run {
                init(Cipher.ENCRYPT_MODE, vaultPublicKey, OAEP)
                doFinal(contentKey)
            }
            val sealed = aes(Cipher.ENCRYPT_MODE, contentKey, iv, associatedData).doFinal(secret)
            return ByteBuffer.allocate(1 + 2 + wrappedKey.size + IV_SIZE + sealed.size)
                .put(vault.toByte())
                .putShort(wrappedKey.size.toShort())
                .put(wrappedKey)
                .put(iv)
                .put(sealed)
                .array()
        } finally {
            contentKey.fill(0)
        }
    }

    /** Which vault key wrapped [blob]: [VAULT_V1] or [VAULT_V2]. */
    fun vault(blob: ByteArray): Int {
        require(blob.size > 3) { "Wrapped key is truncated" }
        val version = blob[0].toInt()
        require(version == VAULT_V1 || version == VAULT_V2) { "Unknown wrapped key format" }
        return version
    }

    /**
     * [rsaDecrypt] decrypts the RSA part with the private key of the vault that [vault] names (a Keystore cipher
     * on the phone).
     */
    fun unwrap(blob: ByteArray, associatedData: ByteArray, rsaDecrypt: (ByteArray) -> ByteArray): ByteArray {
        vault(blob)
        val buf = ByteBuffer.wrap(blob)
        buf.get()
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
