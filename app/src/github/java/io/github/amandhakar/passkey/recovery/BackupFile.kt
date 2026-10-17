package io.github.amandhakar.passkey.recovery

import io.github.amandhakar.securechannel.Hkdf
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The encrypted backup of movable passkeys, safe to keep on Google Drive or anywhere else: it holds no key,
 * and opens only with the backup's 256-bit key, which no single keeper has (see [RecoveryShare]).
 *
 * Format: "PVBK" (4) | version (1) | backup id (16) | salt (16) | GCM nonce (12) | GCM ciphertext and tag.
 * The AES-256 key is HKDF-SHA256(backup key, salt). The header is the associated data, so changing any of it
 * makes opening fail. The backup id says which keepers' pieces belong to the file; it is not secret.
 */
internal object BackupFile {
    private const val MAGIC = "PVBK"
    private const val VERSION = 1
    private const val SALT_SIZE = 16
    private const val NONCE_SIZE = 12
    private const val TAG_BITS = 128
    private const val HEADER_SIZE = MAGIC.length + 1 + RecoveryShare.SET_ID_SIZE + SALT_SIZE
    private const val INFO = "passkey-vault-backup v1 aes-256-gcm"

    /** Longest file [open] will look at: the biggest payload we ever accept, plus the header and tag. */
    const val MAX_FILE_BYTES = 4L * 1024 * 1024 + HEADER_SIZE + NONCE_SIZE + TAG_BITS / 8

    /** Encrypts [plain] under [key] for the backup [setId]. */
    fun seal(plain: ByteArray, setId: ByteArray, key: ByteArray, random: SecureRandom = SecureRandom()): ByteArray {
        require(key.size == RecoveryShare.SECRET_SIZE) { "Backup key must be ${RecoveryShare.SECRET_SIZE} bytes" }
        require(setId.size == RecoveryShare.SET_ID_SIZE) { "Invalid backup id" }
        val salt = ByteArray(SALT_SIZE).also { random.nextBytes(it) }
        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
        val header = MAGIC.toByteArray(Charsets.US_ASCII) + byteArrayOf(VERSION.toByte()) + setId + salt
        val aesKey = deriveKey(key, salt)
        try {
            return header + nonce + cipher(Cipher.ENCRYPT_MODE, aesKey, nonce, header).doFinal(plain)
        } finally {
            aesKey.fill(0)
        }
    }

    /** The backup id in [file]'s header. Throws IllegalArgumentException if it isn't a backup file. */
    fun setId(file: ByteArray): ByteArray {
        require(file.size >= HEADER_SIZE + NONCE_SIZE + TAG_BITS / 8 && file.size <= MAX_FILE_BYTES) { "Not a Passkey Vault backup" }
        require(String(file, 0, MAGIC.length, Charsets.US_ASCII) == MAGIC) { "Not a Passkey Vault backup" }
        require(file[MAGIC.length].toInt() == VERSION) { "Made by a different version of Passkey Vault; update the app" }
        return file.copyOfRange(MAGIC.length + 1, MAGIC.length + 1 + RecoveryShare.SET_ID_SIZE)
    }

    /**
     * Decrypts a file made by [seal]. Throws IllegalArgumentException if it isn't a backup, is from a newer
     * app, or the key is wrong or the file was changed (those last two can't be told apart, by design).
     */
    fun open(file: ByteArray, key: ByteArray): ByteArray {
        require(key.size == RecoveryShare.SECRET_SIZE) { "Backup key must be ${RecoveryShare.SECRET_SIZE} bytes" }
        setId(file)
        val header = file.copyOfRange(0, HEADER_SIZE)
        val salt = file.copyOfRange(HEADER_SIZE - SALT_SIZE, HEADER_SIZE)
        val nonce = file.copyOfRange(HEADER_SIZE, HEADER_SIZE + NONCE_SIZE)
        val aesKey = deriveKey(key, salt)
        try {
            return cipher(Cipher.DECRYPT_MODE, aesKey, nonce, header).doFinal(file, HEADER_SIZE + NONCE_SIZE, file.size - HEADER_SIZE - NONCE_SIZE)
        } catch (_: java.security.GeneralSecurityException) {
            throw IllegalArgumentException("The pieces don't open this file: wrong backup, or the file is damaged")
        } finally {
            aesKey.fill(0)
        }
    }

    private fun deriveKey(key: ByteArray, salt: ByteArray): ByteArray =
        Hkdf.expand(Hkdf.extract(salt, key), INFO.toByteArray(Charsets.US_ASCII), 32)

    private fun cipher(mode: Int, aesKey: ByteArray, nonce: ByteArray, header: ByteArray) =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            updateAAD(header)
        }
}
