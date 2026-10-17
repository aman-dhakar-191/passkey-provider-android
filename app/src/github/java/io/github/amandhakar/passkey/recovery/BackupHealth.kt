package io.github.amandhakar.passkey.recovery

import java.util.concurrent.TimeUnit

/** Who keeps a piece of the backup's key. */
internal enum class KeeperKind { GOOGLE, CARD, PERSON }

/**
 * One keeper of a piece, as the owner's phone remembers it. The phone keeps the piece's check key, never the
 * piece. Times are epoch milliseconds; 0 means never.
 */
internal data class Keeper(
    val x: Int,
    val kind: KeeperKind,
    val label: String,
    val checkKey: ByteArray,
    val addedAt: Long,
    val lastOkAt: Long = 0,
    val lastProblem: String = "",
    val lastProblemAt: Long = 0,
    /** A check sent to a person and not answered yet ([ShareCheck.Challenge.text]), or "". */
    val pendingChallenge: String = "",
) {
    override fun equals(other: Any?) = other is Keeper && other.x == x && other.kind == kind && other.label == label &&
        other.checkKey.contentEquals(checkKey) && other.addedAt == addedAt && other.lastOkAt == lastOkAt &&
        other.lastProblem == lastProblem && other.lastProblemAt == lastProblemAt && other.pendingChallenge == pendingChallenge

    override fun hashCode() = x * 31 + label.hashCode()
}

/** The backup file, as last written. */
internal data class SavedFile(
    val uri: String,
    val sha256: String,
    val writtenAt: Long,
    /** Credential ids of the passkeys in it, to tell when the file is out of date. */
    val passkeyIds: Set<String>,
    val lastOkAt: Long = 0,
    val lastProblem: String = "",
    val lastProblemAt: Long = 0,
)

/** What the owner's phone knows about its backup. */
internal data class BackupSet(
    val setId: ByteArray,
    val createdAt: Long,
    /** The key (x = 0) and the owner's point (x = 255), encrypted under the fingerprint-only vault. */
    val ownerPoints: String,
    val keepers: List<Keeper> = emptyList(),
    val file: SavedFile? = null,
    val lastReminderAt: Long = 0,
    /** Piece numbers ever handed out, including removed keepers': never reused, so no two keepers share a piece. */
    val usedX: Set<Int> = emptySet(),
) {
    override fun equals(other: Any?) = other is BackupSet && other.setId.contentEquals(setId) &&
        other.createdAt == createdAt && other.ownerPoints == ownerPoints && other.keepers == keepers &&
        other.file == file && other.lastReminderAt == lastReminderAt && other.usedX == usedX

    override fun hashCode() = setId.contentHashCode()

    /** The next piece number (1..254) never handed out before. */
    fun nextX(): Int = (1..RecoveryShare.MAX_X).firstOrNull { x -> x !in usedX && keepers.none { it.x == x } }
        ?: throw IllegalStateException("No piece numbers left: use Start over")
}

/**
 * Whether the backup would work today, and what to do if not. A keeper counts as working if its last check
 * passed; it is "due" once that check is older than [CHECK_EVERY_DAYS], so a lost piece is noticed while the
 * phone still works, not after it's gone.
 */
internal object BackupHealth {
    const val CHECK_EVERY_DAYS = 90L
    const val RECOMMENDED_KEEPERS = 3
    private val CHECK_EVERY_MS = TimeUnit.DAYS.toMillis(CHECK_EVERY_DAYS)

    enum class Level { OK, DUE, PROBLEM }

    class Report(val level: Level, val messages: List<String>)

    fun keeper(keeper: Keeper, now: Long): Level = when {
        keeper.lastProblemAt > keeper.lastOkAt -> Level.PROBLEM
        now - keeper.lastOkAt > CHECK_EVERY_MS -> Level.DUE
        else -> Level.OK
    }

    fun file(file: SavedFile?, movableIds: Set<String>, now: Long): Level = when {
        file == null -> Level.PROBLEM
        file.lastProblemAt > maxOf(file.lastOkAt, file.writtenAt) -> Level.PROBLEM
        file.passkeyIds != movableIds -> Level.DUE
        now - maxOf(file.lastOkAt, file.writtenAt) > CHECK_EVERY_MS -> Level.DUE
        else -> Level.OK
    }

    /** The whole backup: [movableIds] are the passkeys that should be in the file. */
    fun report(set: BackupSet, movableIds: Set<String>, now: Long): Report {
        val messages = mutableListOf<String>()
        val levels = set.keepers.map { keeper(it, now) }
        val working = levels.count { it != Level.PROBLEM }
        val checked = levels.count { it == Level.OK }
        val need = RecoveryShare.THRESHOLD

        val fileLevel = file(set.file, movableIds, now)
        when {
            set.file == null -> messages += "No backup file yet: tap Back up now."
            fileLevel == Level.PROBLEM -> messages += "The backup file couldn't be checked: ${set.file.lastProblem.ifBlank { "save it again" }}"
            set.file.passkeyIds != movableIds -> messages += "Passkeys changed since the last backup: tap Back up now."
            fileLevel == Level.DUE -> messages += "Check that the backup file is still there."
        }
        when {
            working < need -> messages += "Restoring needs $need keepers and only $working can be counted on. Add a keeper."
            working < RECOMMENDED_KEEPERS -> messages += "Only $working keepers: if one is lost, you can't restore. Add another."
        }
        set.keepers.zip(levels).forEach { (keeper, level) ->
            when (level) {
                Level.PROBLEM -> messages += "${keeper.label}: ${keeper.lastProblem.ifBlank { "the last check failed" }}"
                Level.DUE -> messages += "${keeper.label}: " + if (keeper.lastOkAt == 0L) "not checked from this phone yet" else "time for a check"
                Level.OK -> Unit
            }
        }
        val level = when {
            fileLevel == Level.PROBLEM || working < need -> Level.PROBLEM
            fileLevel == Level.DUE || checked < RECOMMENDED_KEEPERS || levels.any { it != Level.OK } -> Level.DUE
            else -> Level.OK
        }
        return Report(level, messages)
    }
}
