package io.github.amandhakar.passkey.recovery

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.SecureRandom

class BackupFileTest {
    private val plain = """{"format":"passkey-vault-move","passkeys":[]}""".toByteArray()
    private val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val setId = ByteArray(16).also { SecureRandom().nextBytes(it) }

    private fun otherKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Test
    fun `opens what it sealed and names its backup`() {
        val file = BackupFile.seal(plain, setId, key)
        assertArrayEquals(plain, BackupFile.open(file, key))
        assertArrayEquals(setId, BackupFile.setId(file))
    }

    @Test
    fun `every backup is different, even for the same key and contents`() {
        assertFalse(BackupFile.seal(plain, setId, key).contentEquals(BackupFile.seal(plain, setId, key)))
    }

    @Test
    fun `the file does not contain the contents or the key`() {
        val text = String(BackupFile.seal(plain, setId, key), Charsets.ISO_8859_1)
        assertFalse(text.contains("passkey-vault-move"))
        assertFalse(text.contains(String(key, Charsets.ISO_8859_1)))
    }

    @Test
    fun `a different key does not open it`() {
        val file = BackupFile.seal(plain, setId, key)
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open(file, otherKey()) }
    }

    @Test
    fun `changing any single byte of the file stops it opening`() {
        val file = BackupFile.seal(plain, setId, key)
        for (i in file.indices) {
            val changed = file.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertThrows("byte $i", IllegalArgumentException::class.java) { BackupFile.open(changed, key) }
        }
    }

    @Test
    fun `cut-off, empty, padded and foreign files are refused`() {
        val file = BackupFile.seal(plain, setId, key)
        for (n in listOf(0, 1, 4, 20, 40, 60, file.size - 1)) {
            assertThrows("length $n", IllegalArgumentException::class.java) { BackupFile.open(file.copyOf(n), key) }
        }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open("not a backup at all, just some text, long enough".toByteArray(), key) }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open(file + ByteArray(1), key) }
    }

    @Test
    fun `refuses files bigger than any backup can be`() {
        val huge = ByteArray((BackupFile.MAX_FILE_BYTES + 1).toInt())
        assertThrows(IllegalArgumentException::class.java) { BackupFile.setId(huge) }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open(huge, key) }
    }
}
