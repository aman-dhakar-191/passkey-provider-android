package io.github.amandhakar.passkey.recovery

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupSetJsonTest {
    private val set = BackupSet(
        setId = ByteArray(16) { it.toByte() },
        createdAt = 123,
        ownerPoints = "wrapped",
        keepers = listOf(
            Keeper(1, KeeperKind.GOOGLE, "Google", ByteArray(32) { 1 }, 10, lastOkAt = 20),
            Keeper(2, KeeperKind.PERSON, "Priya", ByteArray(32) { 2 }, 11, lastProblem = "no answer", lastProblemAt = 30, pendingChallenge = "PVC1-X"),
        ),
        file = SavedFile("content://drive/1", "hash", 40, setOf("b", "a"), lastOkAt = 50),
        lastReminderAt = 60,
    )

    @Test
    fun `round-trips through JSON`() {
        assertEquals(set, BackupSetJson.read(JSONObject(BackupSetJson.write(set).toString())))
        val noFile = set.copy(file = null, keepers = emptyList())
        assertEquals(noFile, BackupSetJson.read(JSONObject(BackupSetJson.write(noFile).toString())))
    }

    @Test
    fun `the keeper list in the backup file has no secrets`() {
        val text = BackupSetJson.keeperList(set).toString()
        assertFalse(text.contains("wrapped"))
        assertFalse(text.contains("checkKey"))
        assertFalse(text.contains("PVC1"))
        assertEquals(
            listOf(Triple(1, KeeperKind.GOOGLE, "Google"), Triple(2, KeeperKind.PERSON, "Priya")),
            BackupSetJson.readKeeperList(JSONObject(text)),
        )
    }

    @Test
    fun `a hostile keeper list is cut down, not trusted`() {
        val list = BackupSetJson.readKeeperList(
            JSONObject(
                """{"keepers":[{"x":0,"kind":"CARD","label":"a"},{"x":255,"kind":"CARD","label":"b"},
                {"x":3,"kind":"ROBOT","label":"c"},{"x":4,"kind":"CARD"},{"x":5,"kind":"CARD","label":"${"x".repeat(500)}"},
                {"x":5,"kind":"PERSON","label":"dup"}, null, 7]}""",
            ),
        )
        assertEquals(listOf(5), list.map { it.first })
        assertTrue(list[0].third.length <= BackupSetJson.LABEL_MAX)
        assertEquals(emptyList<Any>(), BackupSetJson.readKeeperList(null))
        assertEquals(emptyList<Any>(), BackupSetJson.readKeeperList(JSONObject("{}")))
    }
}
