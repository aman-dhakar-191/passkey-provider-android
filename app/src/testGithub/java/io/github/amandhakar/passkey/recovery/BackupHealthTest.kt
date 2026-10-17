package io.github.amandhakar.passkey.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

class BackupHealthTest {
    private val day = TimeUnit.DAYS.toMillis(1)
    private val now = 1_000 * day
    private val ids = setOf("a", "b")

    private fun keeper(x: Int, okDaysAgo: Long? = 1, problemDaysAgo: Long? = null) = Keeper(
        x = x, kind = KeeperKind.PERSON, label = "K$x", checkKey = ByteArray(32), addedAt = now - 200 * day,
        lastOkAt = okDaysAgo?.let { now - it * day } ?: 0,
        lastProblem = if (problemDaysAgo != null) "lost it" else "",
        lastProblemAt = problemDaysAgo?.let { now - it * day } ?: 0,
    )

    private fun set(keepers: List<Keeper>, file: SavedFile? = SavedFile("content://x", "h", now - day, ids, now - day)) =
        BackupSet(ByteArray(16), now - 300 * day, "wrapped", keepers, file)

    private fun level(set: BackupSet, movable: Set<String> = ids) = BackupHealth.report(set, movable, now).level

    @Test
    fun `three checked keepers and a current file are healthy`() {
        val report = BackupHealth.report(set(listOf(keeper(1), keeper(2), keeper(3))), ids, now)
        assertEquals(BackupHealth.Level.OK, report.level)
        assertTrue(report.messages.isEmpty())
    }

    @Test
    fun `two keepers can restore but losing one would be fatal`() {
        val report = BackupHealth.report(set(listOf(keeper(1), keeper(2))), ids, now)
        assertEquals(BackupHealth.Level.DUE, report.level)
        assertTrue(report.messages.any { it.contains("Only 2 keepers") })
    }

    @Test
    fun `a failed check counts the keeper out`() {
        assertEquals(BackupHealth.Level.PROBLEM, BackupHealth.keeper(keeper(1, okDaysAgo = 10, problemDaysAgo = 1), now))
        // A later successful check clears it.
        assertEquals(BackupHealth.Level.OK, BackupHealth.keeper(keeper(1, okDaysAgo = 1, problemDaysAgo = 10), now))
        // Two of three failed: restoring isn't possible any more.
        val set = set(listOf(keeper(1), keeper(2, okDaysAgo = 10, problemDaysAgo = 1), keeper(3, okDaysAgo = 10, problemDaysAgo = 1)))
        assertEquals(BackupHealth.Level.PROBLEM, level(set))
    }

    @Test
    fun `checks go stale and unchecked keepers are due`() {
        assertEquals(BackupHealth.Level.DUE, BackupHealth.keeper(keeper(1, okDaysAgo = BackupHealth.CHECK_EVERY_DAYS + 1), now))
        assertEquals(BackupHealth.Level.OK, BackupHealth.keeper(keeper(1, okDaysAgo = BackupHealth.CHECK_EVERY_DAYS - 1), now))
        assertEquals(BackupHealth.Level.DUE, BackupHealth.keeper(keeper(1, okDaysAgo = null), now))
        // Stale keepers still count towards restoring (they probably still have it), but the backup needs a look.
        assertEquals(BackupHealth.Level.DUE, level(set(listOf(keeper(1, 200), keeper(2, 200), keeper(3)))))
    }

    @Test
    fun `the file must exist and hold the current passkeys`() {
        val keepers = listOf(keeper(1), keeper(2), keeper(3))
        assertEquals(BackupHealth.Level.PROBLEM, level(set(keepers, file = null)))
        assertEquals(BackupHealth.Level.DUE, level(set(keepers), movable = ids + "c"))
        val broken = SavedFile("content://x", "h", now - 5 * day, ids, now - 5 * day, "missing", now - day)
        assertEquals(BackupHealth.Level.PROBLEM, level(set(keepers, broken)))
    }

    @Test
    fun `the next piece number skips used ones`() {
        assertEquals(1, set(emptyList()).nextX())
        assertEquals(3, set(listOf(keeper(1), keeper(2))).nextX())
        assertEquals(2, set(listOf(keeper(1), keeper(3))).nextX())
    }
}
