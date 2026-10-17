package io.github.amandhakar.passkey.transfer

import io.github.amandhakar.securechannel.Hkdf
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * An encrypted backup of movable passkeys, safe to put on Google Drive or anywhere else: the file is useless
 * without its **recovery key**, a random 256-bit secret the app shows once when the backup is made.
 *
 * The recovery key is random, not a password the person picks, so there is nothing to guess: an attacker with
 * the file would have to break AES-256. That is also why no slow password hash (Argon2, scrypt) is needed.
 * The price is that the person must keep the key themselves (a password manager or paper). Lose it and the
 * file can never be opened, by anyone, including this app.
 *
 * Format: "PVBK" (4) | version (1) | salt (16) | GCM nonce (12) | GCM ciphertext and tag.
 * The AES-256 key is HKDF-SHA256(recovery key, salt). The header is the associated data, so changing any of it
 * makes opening fail. A fresh salt, nonce and recovery key are made for every backup.
 */
internal object BackupFile {
    private const val MAGIC = "PVBK"
    private const val VERSION = 1
    private const val SALT_SIZE = 16
    private const val NONCE_SIZE = 12
    private const val TAG_BITS = 128
    private const val HEADER_SIZE = MAGIC.length + 1 + SALT_SIZE
    const val KEY_SIZE = 32
    private const val CHECK_SIZE = 3
    private const val INFO = "passkey-vault-backup v1 aes-256-gcm"

    /** Longest file [open] will look at: the biggest payload we ever accept, plus the header and tag. */
    const val MAX_FILE_BYTES = 4L * 1024 * 1024 + HEADER_SIZE + NONCE_SIZE + TAG_BITS / 8

    /** Letters and digits without the look-alikes (no 0, 1, I, O): 32 symbols, 5 bits each. */
    private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    fun newRecoveryKey(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(KEY_SIZE).also { random.nextBytes(it) }

    /**
     * The key as people copy it: 35 bytes (the key and a 3-byte check) as 56 letters and digits in 14 groups of
     * four, e.g. `ABCD-EFGH-…`. The check catches typos when the key is typed back in.
     */
    fun recoveryText(key: ByteArray): String {
        require(key.size == KEY_SIZE) { "Recovery key must be $KEY_SIZE bytes" }
        val data = key + check(key)
        val bits = StringBuilder()
        data.forEach { bits.append(Integer.toBinaryString((it.toInt() and 0xff) or 0x100).substring(1)) }
        return bits.chunked(5).map { ALPHABET[it.toString().toInt(2)] }.joinToString("").chunked(4).joinToString("-")
    }

    /** Reads what [recoveryText] made. Ignores case, spaces and dashes; throws IllegalArgumentException on a typo. */
    fun parseRecoveryText(text: String): ByteArray {
        val symbols = text.uppercase().filter { it != '-' && !it.isWhitespace() }
        val invalid = IllegalArgumentException("That isn't a valid recovery key. Check it for typos.")
        if (symbols.length != (KEY_SIZE + CHECK_SIZE) * 8 / 5) throw invalid
        val bits = StringBuilder()
        for (symbol in symbols) {
            val value = ALPHABET.indexOf(symbol)
            if (value < 0) throw invalid
            bits.append(Integer.toBinaryString(value or 0x20).substring(1))
        }
        val data = bits.chunked(8).map { it.toString().toInt(2).toByte() }.toByteArray()
        val key = data.copyOfRange(0, KEY_SIZE)
        if (!MessageDigest.isEqual(data.copyOfRange(KEY_SIZE, data.size), check(key))) throw invalid
        return key
    }

    private fun check(key: ByteArray) = MessageDigest.getInstance("SHA-256").digest(key).copyOf(CHECK_SIZE)

    /** Encrypts [plain] (a [TransferPayload]) under [key]. */
    fun seal(plain: ByteArray, key: ByteArray, random: SecureRandom = SecureRandom()): ByteArray {
        require(key.size == KEY_SIZE) { "Recovery key must be $KEY_SIZE bytes" }
        val salt = ByteArray(SALT_SIZE).also { random.nextBytes(it) }
        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
        val header = MAGIC.toByteArray(Charsets.US_ASCII) + byteArrayOf(VERSION.toByte()) + salt
        val aesKey = deriveKey(key, salt)
        try {
            return header + nonce + cipher(Cipher.ENCRYPT_MODE, aesKey, nonce, header).doFinal(plain)
        } finally {
            aesKey.fill(0)
        }
    }

    /**
     * Decrypts a file made by [seal]. Throws IllegalArgumentException if it isn't a backup, is from a newer
     * app, or the key is wrong or the file was changed (those last two can't be told apart, by design).
     */
    fun open(file: ByteArray, key: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "Recovery key must be $KEY_SIZE bytes" }
        require(file.size >= HEADER_SIZE + NONCE_SIZE + TAG_BITS / 8 && file.size <= MAX_FILE_BYTES) { "Not a Passkey Vault backup" }
        require(String(file, 0, MAGIC.length, Charsets.US_ASCII) == MAGIC) { "Not a Passkey Vault backup" }
        require(file[MAGIC.length].toInt() == VERSION) { "Made by a different version of Passkey Vault; update the app" }
        val header = file.copyOfRange(0, HEADER_SIZE)
        val salt = file.copyOfRange(MAGIC.length + 1, HEADER_SIZE)
        val nonce = file.copyOfRange(HEADER_SIZE, HEADER_SIZE + NONCE_SIZE)
        val aesKey = deriveKey(key, salt)
        try {
            return cipher(Cipher.DECRYPT_MODE, aesKey, nonce, header).doFinal(file, HEADER_SIZE + NONCE_SIZE, file.size - HEADER_SIZE - NONCE_SIZE)
        } catch (_: java.security.GeneralSecurityException) {
            throw IllegalArgumentException("Wrong recovery key, or the file is damaged")
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
