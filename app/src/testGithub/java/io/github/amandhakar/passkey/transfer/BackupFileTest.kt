package io.github.amandhakar.passkey.transfer

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupFileTest {
    private val plain = """{"format":"passkey-vault-move","passkeys":[]}""".toByteArray()
    private val key = BackupFile.newRecoveryKey()

    @Test
    fun `opens what it sealed`() {
        assertArrayEquals(plain, BackupFile.open(BackupFile.seal(plain, key), key))
    }

    @Test
    fun `every backup is different, even for the same key and contents`() {
        assertFalse(BackupFile.seal(plain, key).contentEquals(BackupFile.seal(plain, key)))
    }

    @Test
    fun `the file does not contain the contents or the key`() {
        val file = BackupFile.seal(plain, key)
        val text = String(file, Charsets.ISO_8859_1)
        assertFalse(text.contains("passkey-vault-move"))
        assertFalse(text.contains(String(key, Charsets.ISO_8859_1)))
    }

    @Test
    fun `a different key does not open it`() {
        val file = BackupFile.seal(plain, key)
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open(file, BackupFile.newRecoveryKey()) }
    }

    @Test
    fun `changing any single byte of the file stops it opening`() {
        val file = BackupFile.seal(plain, key)
        for (i in file.indices) {
            val changed = file.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertThrows("byte $i", IllegalArgumentException::class.java) { BackupFile.open(changed, key) }
        }
    }

    @Test
    fun `cut-off, empty and foreign files are refused`() {
        val file = BackupFile.seal(plain, key)
        for (n in listOf(0, 1, 4, 20, 32, file.size - 1)) {
            assertThrows("length $n", IllegalArgumentException::class.java) { BackupFile.open(file.copyOf(n), key) }
        }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open("not a backup at all, just some text".toByteArray(), key) }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open(file + ByteArray(1), key) }
    }

    @Test
    fun `refuses files bigger than any backup can be`() {
        val huge = ByteArray((BackupFile.MAX_FILE_BYTES + 1).toInt())
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open(huge, key) }
    }

    @Test
    fun `recovery key text round-trips and is easy to type`() {
        val text = BackupFile.recoveryText(key)
        assertEquals(14 * 4 + 13, text.length)
        assertTrue(text.matches(Regex("([A-Z2-9]{4}-){13}[A-Z2-9]{4}")))
        assertTrue("no look-alikes", text.none { it in "01IO" })
        assertArrayEquals(key, BackupFile.parseRecoveryText(text))
        // Case, spaces and missing dashes don't matter when typing it back.
        assertArrayEquals(key, BackupFile.parseRecoveryText(text.lowercase().replace('-', ' ')))
        assertArrayEquals(key, BackupFile.parseRecoveryText(text.replace("-", "")))
    }

    @Test
    fun `a typo in the recovery key is caught`() {
        val text = BackupFile.recoveryText(key)
        for (i in text.indices) {
            if (text[i] == '-') continue
            val other = if (text[i] == 'A') 'B' else 'A'
            val typo = text.substring(0, i) + other + text.substring(i + 1)
            assertThrows("char $i", IllegalArgumentException::class.java) { BackupFile.parseRecoveryText(typo) }
        }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.parseRecoveryText("") }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.parseRecoveryText(text.dropLast(1)) }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.parseRecoveryText(text + "A") }
        assertThrows(IllegalArgumentException::class.java) { BackupFile.parseRecoveryText(text.replaceFirst(text[0], '0')) }
    }

    @Test
    fun `a well-formed key that is not the file's key is refused by the file`() {
        val file = BackupFile.seal(plain, key)
        val other = BackupFile.newRecoveryKey()
        // A well-formed key that isn't this file's key parses fine and is then refused by the file itself.
        val parsed = BackupFile.parseRecoveryText(BackupFile.recoveryText(other))
        assertThrows(IllegalArgumentException::class.java) { BackupFile.open(file, parsed) }
    }
}
