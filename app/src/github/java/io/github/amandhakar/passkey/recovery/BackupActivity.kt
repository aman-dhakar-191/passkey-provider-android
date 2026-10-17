@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package io.github.amandhakar.passkey.recovery

import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.provider.verifyUser
import io.github.amandhakar.passkey.provider.verifyWithFingerprint
import io.github.amandhakar.passkey.transfer.MovablePasskeys
import io.github.amandhakar.passkey.transfer.MovingPasskey
import io.github.amandhakar.passkey.transfer.PasskeyBundle
import io.github.amandhakar.passkey.transfer.TransferPayload
import io.github.amandhakar.passkey.ui.PasskeyTheme
import io.github.amandhakar.passkey.webauthn.Base64Url
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.Closeable
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.DateFormat
import java.util.Date

/**
 * Backup & recovery (GitHub build).
 *
 * The movable passkeys go into one encrypted file ([BackupFile]) that can live anywhere (Google Drive, another
 * cloud app, the phone). Its key is never shown and never stored whole outside this phone: it is split into
 * pieces ([Shamir], [RecoveryShare]), any two of which rebuild it, and each piece goes to a different keeper:
 * Google ([GoogleKeeper], locked with the screen lock), a printed card ([ShareCard]) or another person's
 * Passkey Vault ([QrLink]). The phone checks now and then that the keepers still have their pieces
 * ([ShareCheck], [BackupHealth]) and reminds the person when a check is due ([BackupReminderWorker]).
 *
 * The same screen lets this phone keep a piece for someone else, answer their checks, and give it back.
 */
class BackupActivity : FragmentActivity() {
    private sealed interface Phase {
        data object Idle : Phase
        data class Busy(val what: String) : Phase
        class ShowingQr(val qr: Bitmap, val title: String, val hint: String) : Phase
        class AskText(val title: String, val hint: String, val label: String, val secret: Boolean, val answer: CompletableDeferred<String?>) : Phase
        class AskYesNo(val title: String, val text: String, val yes: String, val no: String, val answer: CompletableDeferred<Boolean>) : Phase
        class ShowCode(val title: String, val text: String, val code: String, val shareText: String) : Phase
        class Confirm(val passkeys: List<String>, val skipped: Int, val answer: CompletableDeferred<Boolean>) : Phase
        class Collect(val have: List<String>, val googleTried: Boolean, val answer: CompletableDeferred<Source?>) : Phase
    }

    /** Where a piece comes from when restoring. */
    private enum class Source { GOOGLE, CARD_SCAN, CARD_TYPE, PERSON }

    private class LogLine(val ok: Boolean, val text: String)

    private val phase = mutableStateOf<Phase>(Phase.Idle)
    private val log = mutableStateListOf<LogLine>()
    private var job: Job? = null
    private val open = mutableListOf<Closeable>()

    // The system's file picker: the person chooses where the backup goes (Google Drive, another cloud app,
    // the phone). The app needs no storage permission, Google account or network access for it.
    private var picked: CompletableDeferred<Uri?>? = null
    private val createFile = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { picked?.complete(it) }
    private val openFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { picked?.complete(it) }

    private val store by lazy { RecoveryStore.get(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // QR codes here carry one-time secrets: keep them out of screenshots, recordings and Recents.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        if (store.set.value != null) BackupReminderWorker.schedule(this)
        setContent {
            PasskeyTheme {
                Surface(Modifier.fillMaxSize()) { Screen() }
            }
        }
    }

    override fun onDestroy() {
        stop()
        super.onDestroy()
    }

    // ---- plumbing ---------------------------------------------------------------------------------------

    private fun note(ok: Boolean, text: String) {
        runOnUiThread { log.add(0, LogLine(ok, text)) }
        ProviderErrors.note(this, "Backup: $text")
    }

    private fun stop() {
        synchronized(open) {
            open.forEach { runCatching { it.close() } }
            open.clear()
        }
        job?.cancel()
        job = null
        when (val current = phase.value) {
            is Phase.AskText -> current.answer.complete(null)
            is Phase.AskYesNo -> current.answer.complete(false)
            is Phase.Confirm -> current.answer.complete(false)
            is Phase.Collect -> current.answer.complete(null)
            else -> Unit
        }
        picked?.complete(null)
        phase.value = Phase.Idle
    }

    private fun track(closeable: Closeable) {
        synchronized(open) { open += closeable }
    }

    private fun session(block: suspend () -> Unit) {
        if (phase.value != Phase.Idle) return
        phase.value = Phase.Busy("Starting…")
        job = lifecycleScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                note(false, e.message ?: e.javaClass.simpleName)
            } finally {
                synchronized(open) {
                    open.forEach { runCatching { it.close() } }
                    open.clear()
                }
                phase.value = Phase.Idle
            }
        }
    }

    private suspend fun pick(launch: () -> Unit): Uri? {
        val result = CompletableDeferred<Uri?>()
        picked = result
        launch()
        return result.await()
    }

    private suspend fun ask(title: String, hint: String, label: String, secret: Boolean = false): String? {
        val answer = CompletableDeferred<String?>()
        phase.value = Phase.AskText(title, hint, label, secret, answer)
        return answer.await()?.trim()?.takeIf { it.isNotEmpty() }
    }

    private suspend fun yesNo(title: String, text: String, yes: String, no: String = "Cancel"): Boolean {
        val answer = CompletableDeferred<Boolean>()
        phase.value = Phase.AskYesNo(title, text, yes, no, answer)
        return answer.await()
    }

    private fun cancelled(): Nothing = throw IllegalStateException("Cancelled")

    private fun now() = System.currentTimeMillis()

    private fun day(time: Long): String = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(time))

    private fun sha256(data: ByteArray) = Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(data))

    private fun shareText(text: String) {
        startActivity(
            Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text), null),
        )
    }

    // ---- the owner's key -------------------------------------------------------------------------------

    private fun ownerData(setId: ByteArray) = "passkey-vault backup owner v1".toByteArray() + setId

    /** Needs a fingerprint: the key and the owner's point, from the fingerprint-only vault. */
    private suspend fun ownerPoints(set: BackupSet, why: String): List<Shamir.Point> {
        if (!MovablePasskeys.fingerprintReady(this)) {
            throw IllegalStateException("This needs a fingerprint; the screen lock alone isn't enough. Set one up in Settings.")
        }
        if (!verifyWithFingerprint("Backup", why)) cancelled()
        val bytes = try {
            withContext(Dispatchers.Default) { MovablePasskeys.unwrapSecret(set.ownerPoints, ownerData(set.setId)) }
        } catch (e: IllegalStateException) {
            throw IllegalStateException(
                "This phone can no longer open the backup key (fingerprints were changed). Your keepers can still " +
                    "restore the existing backup; to keep backing up from this phone, use Start over.",
                e,
            )
        }
        try {
            require(bytes.size == 2 * RecoveryShare.SECRET_SIZE) { "The stored backup key is damaged" }
            return listOf(
                Shamir.Point(0, bytes.copyOfRange(0, RecoveryShare.SECRET_SIZE)),
                Shamir.Point(RecoveryShare.OWNER_X, bytes.copyOfRange(RecoveryShare.SECRET_SIZE, bytes.size)),
            )
        } finally {
            bytes.fill(0)
        }
    }

    private fun wrapOwner(setId: ByteArray, points: List<Shamir.Point>): String {
        val bytes = points[0].y + points[1].y
        try {
            return MovablePasskeys.wrapSecret(bytes, ownerData(setId))
        } finally {
            bytes.fill(0)
        }
    }

    private fun List<Shamir.Point>.wipe() = forEach { it.y.fill(0) }

    private fun requireSet(): BackupSet = store.set.value ?: throw IllegalStateException("Set up the backup first")

    /** A new piece for a new keeper, made from the owner's points (needs a fingerprint). */
    private suspend fun newPiece(set: BackupSet, why: String): RecoveryShare {
        val points = ownerPoints(set, why)
        try {
            return RecoveryShare.issue(set.setId, points, listOf(set.nextX())).single()
        } finally {
            points.wipe()
        }
    }

    private fun addKeeper(kind: KeeperKind, label: String, share: RecoveryShare, okNow: Boolean) {
        val time = now()
        store.update { set ->
            set?.copy(
                keepers = set.keepers.filterNot { it.x == share.x } +
                    Keeper(share.x, kind, label.take(BackupSetJson.LABEL_MAX), share.checkKey(), time, lastOkAt = if (okNow) time else 0),
                usedX = set.usedX + share.x,
            )
        }
    }

    // ---- owner: set up, back up, keepers ---------------------------------------------------------------

    private fun setUp() = session {
        if (!MovablePasskeys.fingerprintReady(this)) {
            throw IllegalStateException("Backup needs a fingerprint; the screen lock alone isn't enough. Set one up in Settings.")
        }
        if (store.set.value != null) throw IllegalStateException("A backup is already set up")
        if (!verifyWithFingerprint("Set up backup", "Makes a new key for your encrypted backup")) cancelled()
        phase.value = Phase.Busy("Making the backup key…")
        val setId = ByteArray(RecoveryShare.SET_ID_SIZE).also { SecureRandom().nextBytes(it) }
        val points = RecoveryShare.newOwnerPoints()
        val wrapped = try {
            withContext(Dispatchers.Default) { wrapOwner(setId, points) }
        } finally {
            points.wipe()
        }
        store.update { BackupSet(setId, now(), wrapped) }
        BackupReminderWorker.schedule(this)
        note(true, "Backup set up. Next: Back up now, then add keepers (Google, a printed card, someone you trust).")
    }

    /** Writes the backup file: to where it was last saved, or where the person picks. */
    private fun backUpNow(newPlace: Boolean) = session {
        val set = requireSet()
        val movable = PasskeyBundle.movable(this)
        if (movable.isEmpty()) {
            throw IllegalStateException("No movable passkeys to back up. Only passkeys made as \"Can be moved\" can be backed up.")
        }
        val points = ownerPoints(set, "Back up ${movable.size} passkey(s) into the encrypted file")
        phase.value = Phase.Busy("Encrypting ${movable.size} passkey(s)…")
        val file = try {
            withContext(Dispatchers.Default) {
                val payload = PasskeyBundle.encode(this@BackupActivity, movable, BackupSetJson.keeperList(set))
                try {
                    BackupFile.seal(payload, set.setId, points[0].y)
                } finally {
                    payload.fill(0)
                }
            }
        } finally {
            points.wipe()
        }

        val previous = set.file?.uri?.takeIf { !newPlace }?.let { Uri.parse(it) }
        val updated = previous != null && runCatching { writeAndVerify(previous, file) }.getOrDefault(false)
        if (previous != null && !updated) note(false, "Couldn't update the backup file where it was; choose where to save it.")
        val uri: Uri = if (updated) {
            previous!!
        } else {
            phase.value = Phase.Busy("Choose where to save the backup file")
            val chosen = pick { createFile.launch("passkey-vault-backup.pvbackup") } ?: cancelled()
            if (!writeAndVerify(chosen, file)) throw IOException("The file didn't save correctly there. Choose another place.")
            chosen
        }
        runCatching {
            contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        }
        val time = now()
        val ids = movable.map { it.credentialId }.toSet()
        store.update { it?.copy(file = SavedFile(uri.toString(), sha256(file), time, ids, lastOkAt = time)) }
        PasskeyStore.get(this).markBackedUp(ids)
        note(true, "Backed up ${movable.size} passkey(s) to the encrypted file. It opens only with two of your keepers' pieces.")
    }

    /** Writes [data] to [uri] and reads it back, since some storage apps ignore truncation. */
    private suspend fun writeAndVerify(uri: Uri, data: ByteArray): Boolean = withContext(Dispatchers.IO) {
        val out = runCatching { contentResolver.openOutputStream(uri, "wt") }.getOrNull()
            ?: contentResolver.openOutputStream(uri, "w")
            ?: throw IOException("Couldn't write there")
        out.use { it.write(data) }
        readBounded(uri)?.contentEquals(data) == true
    }

    private suspend fun readBounded(uri: Uri): ByteArray? = withContext(Dispatchers.IO) {
        val input = contentResolver.openInputStream(uri) ?: return@withContext null
        // One byte more than any real backup, so an oversized file is refused without reading it all.
        input.use { it.readNBytes(BackupFile.MAX_FILE_BYTES.toInt() + 1) }
    }

    private fun checkFile() = session {
        val set = requireSet()
        val saved = set.file ?: throw IllegalStateException("No backup file yet: tap Back up now")
        phase.value = Phase.Busy("Checking the backup file…")
        val problem = try {
            val data = readBounded(Uri.parse(saved.uri))
            when {
                data == null -> "can't be opened"
                sha256(data) != saved.sha256 -> "it has changed since it was saved; tap Back up now"
                else -> null
            }
        } catch (e: Exception) {
            "can't be opened (${e.message ?: e.javaClass.simpleName}); tap Back up now"
        }
        val time = now()
        store.update { s ->
            s?.copy(
                file = s.file?.let {
                    if (problem == null) it.copy(lastOkAt = time) else it.copy(lastProblem = "The backup file $problem", lastProblemAt = time)
                },
            )
        }
        note(problem == null, if (problem == null) "The backup file is there and unchanged." else "The backup file $problem.")
    }

    private fun addGoogle() = session {
        val set = requireSet()
        if (set.keepers.any { it.kind == KeeperKind.GOOGLE }) throw IllegalStateException("Google already keeps a piece")
        if (!GoogleKeeper.endToEndEncrypted(this)) {
            throw IllegalStateException(
                "Google's backup isn't end-to-end encrypted on this phone (it needs a screen lock), so Passkey Vault " +
                    "won't give Google a piece. Use a printed card or a person instead.",
            )
        }
        val share = newPiece(set, "Give Google a piece of the backup key")
        try {
            phase.value = Phase.Busy("Saving Google's piece…")
            GoogleKeeper.store(this, share)
            addKeeper(KeeperKind.GOOGLE, "Google", share, okNow = true)
        } finally {
            share.wipe()
        }
        note(
            true,
            "Google keeps a piece, end-to-end encrypted with your screen lock. It comes back when you set up a new " +
                "phone from your Google backup. Make sure Google backup is on (Settings → Google → Backup).",
        )
    }

    private fun addCard() = session {
        val set = requireSet()
        if (!yesNo(
                "Print a card",
                "The card is one piece of the key, as a QR code. Print it on paper and keep it at home. Don't save it " +
                    "as a photo or to Google Drive or e-mail: with Google's piece, that would let Google restore alone.",
                "Print",
            )
        ) cancelled()
        val share = newPiece(set, "Print a piece of the backup key")
        val pdf = try {
            withContext(Dispatchers.Default) { ShareCard.pdf(share, set.createdAt) }
        } catch (e: Exception) {
            share.wipe()
            throw e
        }
        print("Passkey Vault key piece ${share.x}", pdf)
        if (!yesNo("Did the card print?", "Add it as a keeper only if you have it on paper.", "Yes, I have the card", "No")) {
            share.wipe()
            note(false, "Card not added. Its piece isn't counted; print again when you can.")
            return@session
        }
        addKeeper(KeeperKind.CARD, "Printed card ${share.x}", share, okNow = true)
        share.wipe()
        note(true, "Printed card added. If you saved it as a PDF to print, delete that file now.")
    }

    private fun print(name: String, pdf: ByteArray) {
        val adapter = object : PrintDocumentAdapter() {
            override fun onLayout(old: PrintAttributes?, new: PrintAttributes, cancel: CancellationSignal, callback: PrintDocumentAdapter.LayoutResultCallback, extras: Bundle?) {
                if (cancel.isCanceled) {
                    callback.onLayoutCancelled()
                    return
                }
                callback.onLayoutFinished(
                    PrintDocumentInfo.Builder("$name.pdf").setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT).setPageCount(1).build(),
                    old != new,
                )
            }

            override fun onWrite(pages: Array<out PageRange>, destination: ParcelFileDescriptor, cancel: CancellationSignal, callback: PrintDocumentAdapter.WriteResultCallback) {
                try {
                    FileOutputStream(destination.fileDescriptor).use { it.write(pdf) }
                    callback.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
                } catch (e: IOException) {
                    callback.onWriteFailed(e.message)
                }
            }

            override fun onFinish() = pdf.fill(0)
        }
        getSystemService(PrintManager::class.java).print(name, adapter, null)
    }

    private fun addPerson() = session {
        val set = requireSet()
        val label = ask(
            "Who keeps this piece?",
            "Someone you trust, or your own spare phone or tablet. They need Passkey Vault and must be next to you, " +
                "on the same Wi-Fi. On their phone: ⋮ → Backup & recovery → Keep a piece for someone.",
            "Their name",
        ) ?: cancelled()
        val share = newPiece(set, "Give $label a piece of the backup key")
        try {
            phase.value = Phase.Busy("Scan the QR code on $label's phone")
            val data = JSONObject().put("share", share.text()).toString().toByteArray()
            try {
                QrLink.sendOne(this, QrLink.KEEP, data, ::track)
            } finally {
                data.fill(0)
            }
            addKeeper(KeeperKind.PERSON, label, share, okNow = true)
        } finally {
            share.wipe()
        }
        note(true, "$label keeps a piece. Alone it opens nothing.")
    }

    private fun check(keeper: Keeper) = when (keeper.kind) {
        KeeperKind.GOOGLE -> checkGoogle(keeper)
        KeeperKind.CARD -> checkCard(keeper)
        KeeperKind.PERSON -> askPerson(keeper)
    }

    private fun recordCheck(keeper: Keeper, problem: String?) {
        val time = now()
        store.updateKeeper(keeper.x) {
            if (problem == null) it.copy(lastOkAt = time, pendingChallenge = "") else it.copy(lastProblem = problem, lastProblemAt = time)
        }
        note(problem == null, "${keeper.label}: " + (problem ?: "piece checked, all good"))
    }

    private fun matches(keeper: Keeper, share: RecoveryShare, set: BackupSet) =
        share.setId.contentEquals(set.setId) && share.x == keeper.x &&
            MessageDigest.isEqual(share.checkKey(), keeper.checkKey)

    private fun checkGoogle(keeper: Keeper) = session {
        val set = requireSet()
        phase.value = Phase.Busy("Checking Google's piece…")
        val share = GoogleKeeper.read(this)
        val problem = when {
            share == null -> "Google's piece is missing from this phone. Remove it and add Google again."
            !matches(keeper, share, set) -> "Google holds a different piece. Remove it and add Google again."
            !GoogleKeeper.endToEndEncrypted(this) -> "Google's backup isn't end-to-end encrypted any more (screen lock removed?), so the piece stays off Google's cloud."
            else -> null
        }
        // Saving it again keeps Google's cloud copy fresh.
        if (problem == null && share != null) GoogleKeeper.store(this, share)
        share?.wipe()
        recordCheck(keeper, problem)
    }

    private fun checkCard(keeper: Keeper) = session {
        val set = requireSet()
        val scanned = QrLink.scan(this)
        val share = runCatching { RecoveryShare.parse(scanned) }.getOrNull()
        try {
            // Scanning the wrong code says nothing about this card being lost, so only a match is recorded.
            when {
                share == null -> note(false, "${keeper.label}: that isn't a Passkey Vault card. Nothing recorded.")
                !matches(keeper, share, set) -> note(
                    false,
                    "${keeper.label}: that's a different card (piece ${share.x}" +
                        (if (!share.setId.contentEquals(set.setId)) ", another backup" else "") + "). Nothing recorded.",
                )
                else -> recordCheck(keeper, null)
            }
        } finally {
            share?.wipe()
        }
    }

    /** Sends a check through any messaging app; the person's Passkey Vault answers with a short code. */
    private fun askPerson(keeper: Keeper) {
        val set = store.set.value ?: return
        val challenge = ShareCheck.newChallenge(set.setId, keeper.x).text()
        store.updateKeeper(keeper.x) { it.copy(pendingChallenge = challenge) }
        shareText(
            "Passkey Vault: please check the backup piece you keep for me. Open Passkey Vault → ⋮ → Backup & " +
                "recovery → Answer a check, paste this whole message, and send me the answer it shows.\n\n$challenge",
        )
        note(true, "Check sent to ${keeper.label}. Paste their answer here when it comes.")
    }

    private fun enterAnswer(keeper: Keeper) = session {
        val pending = keeper.pendingChallenge.takeIf { it.isNotBlank() } ?: throw IllegalStateException("Send a check first")
        val reply = ask("${keeper.label}'s answer", "Paste the message with their answer (it starts with ${ShareCheck.ANSWER_PREFIX}).", "Answer")
            ?: cancelled()
        val ok = ShareCheck.verify(keeper.checkKey, ShareCheck.parseChallenge(pending), reply)
        if (ok) {
            recordCheck(keeper, null)
        } else if (!reply.uppercase().contains(ShareCheck.ANSWER_PREFIX)) {
            note(false, "No answer found in that text. Paste the whole message.")
        } else {
            recordCheck(keeper, "the answer didn't match: they may have lost the piece, or answered an older check. Send a new check.")
        }
    }

    private fun removeKeeper(keeper: Keeper) = session {
        if (!yesNo(
                "Remove ${keeper.label}?",
                "It stops being counted. The piece itself still exists where it is: if it could be in the wrong hands, " +
                    "use Start over instead, which makes a new key.",
                "Remove",
            )
        ) cancelled()
        if (keeper.kind == KeeperKind.GOOGLE) runCatching { GoogleKeeper.delete(this) }
        store.update { set -> set?.copy(keepers = set.keepers.filterNot { it.x == keeper.x }) }
        note(true, "${keeper.label} removed.")
    }

    private fun startOver() = session {
        if (!yesNo(
                "Start over with a new key?",
                "Every keeper's piece and every earlier backup file stop matching this phone's backup. You then back up " +
                    "again and add keepers again. Delete old backup files: old pieces can still open those.",
                "Start over",
            )
        ) cancelled()
        if (store.set.value?.keepers?.any { it.kind == KeeperKind.GOOGLE } == true) runCatching { GoogleKeeper.delete(this) }
        store.update { null }
        note(true, "The old backup key is gone from this phone. Tap Set up backup to make a new one.")
    }

    // ---- restore ---------------------------------------------------------------------------------------

    private fun restore() = session {
        // Restored passkeys are locked under the fingerprint-only vault, which needs a fingerprint enrolled.
        if (!MovablePasskeys.fingerprintReady(this)) {
            throw IllegalStateException("Restoring needs a fingerprint on this phone. Set one up in Settings first.")
        }
        phase.value = Phase.Busy("Choose the backup file")
        val uri = pick { openFile.launch(arrayOf("*/*")) } ?: cancelled()
        val file = readBounded(uri) ?: throw IOException("Couldn't read that file")
        val setId = BackupFile.setId(file)

        val pieces = mutableListOf<RecoveryShare>()
        var googleTried = false
        try {
            while (pieces.size < RecoveryShare.THRESHOLD) {
                val answer = CompletableDeferred<Source?>()
                phase.value = Phase.Collect(pieces.map { "Piece ${it.x}" }, googleTried, answer)
                val source = answer.await() ?: cancelled()
                val piece = try {
                    when (source) {
                        Source.GOOGLE -> {
                            googleTried = true
                            phase.value = Phase.Busy("Asking Google…")
                            GoogleKeeper.read(this) ?: throw IllegalStateException(
                                "Google has no piece on this phone. It comes back only when the phone is set up from your Google backup.",
                            )
                        }
                        Source.CARD_SCAN -> RecoveryShare.parse(QrLink.scan(this))
                        Source.CARD_TYPE -> RecoveryShare.parse(
                            ask("Type the card", "The letters and digits under the QR code, starting with ${RecoveryShare.TEXT_PREFIX}", "Card text", secret = true)
                                ?: continue,
                        )
                        Source.PERSON -> receivePiece()
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    note(false, e.message ?: e.javaClass.simpleName)
                    continue
                }
                when {
                    !piece.setId.contentEquals(setId) -> note(false, "Piece ${piece.x} belongs to a different backup.").also { piece.wipe() }
                    pieces.any { it.x == piece.x } -> note(false, "You already gave piece ${piece.x}. Another keeper is needed.").also { piece.wipe() }
                    else -> {
                        pieces += piece
                        note(true, "Got piece ${piece.x}.")
                    }
                }
            }

            phase.value = Phase.Busy("Opening the backup…")
            val points = RecoveryShare.combine(pieces)
            try {
                val payload = withContext(Dispatchers.Default) { BackupFile.open(file, points[0].y) }
                val keepers = BackupSetJson.readKeeperList(TransferPayload.recovery(payload))
                importPayload(payload)
                adopt(setId, points, keepers, pieces.map { it.x }.toSet(), uri, file)
            } finally {
                points.wipe()
            }
        } finally {
            pieces.forEach { it.wipe() }
        }
    }

    /** Shows a QR code for a keeper's phone to scan; it sends the piece back. */
    private suspend fun receivePiece(): RecoveryShare {
        val bytes = QrLink.receiveOne(
            QrLink.RETURN,
            ::track,
            show = { qr, _ ->
                phase.value = Phase.ShowingQr(
                    qr,
                    "Let your keeper scan this",
                    "On their phone: Passkey Vault → ⋮ → Backup & recovery → Give back. Both phones on the same Wi-Fi or hotspot.",
                )
            },
            ignored = { note(false, it) },
        )
        try {
            return RecoveryShare.parse(JSONObject(String(bytes)).getString("share"))
        } finally {
            bytes.fill(0)
        }
    }

    /** Asks before adding, like a received transfer; wipes [payload] and the private keys. */
    private suspend fun importPayload(payload: ByteArray) {
        var incoming = emptyList<MovingPasskey>()
        try {
            incoming = withContext(Dispatchers.Default) { TransferPayload.decode(payload) }
            val (new, already) = PasskeyBundle.partition(this, incoming)
            val answer = CompletableDeferred<Boolean>()
            phase.value = Phase.Confirm(PasskeyBundle.describe(new), already.size, answer)
            if (new.isEmpty() || !answer.await()) {
                note(true, "Nothing added" + if (already.isNotEmpty()) " (${already.size} already on this phone)" else "")
                return
            }
            phase.value = Phase.Busy("Adding passkeys…")
            val (added, skipped) = withContext(Dispatchers.Default) { PasskeyBundle.addAll(this@BackupActivity, new) }
            note(true, "Restored $added passkey(s)" + (already.size + skipped).let { if (it > 0) ", $it already on this phone" else "" })
        } finally {
            incoming.forEach { it.privateKey.fill(0) }
            payload.fill(0)
        }
    }

    /** After a restore, this phone takes over the backup and its keepers (their pieces still fit). */
    private fun adopt(
        setId: ByteArray,
        points: List<Shamir.Point>,
        keepers: List<Triple<Int, KeeperKind, String>>,
        used: Set<Int>,
        uri: Uri,
        file: ByteArray,
    ) {
        val current = store.set.value
        if (current != null && !current.setId.contentEquals(setId)) {
            note(true, "This phone already has its own backup; the restored passkeys go into its next backup.")
            return
        }
        val time = now()
        val pieces = RecoveryShare.issue(setId, points, keepers.map { it.first })
        val list = keepers.zip(pieces).map { (k, piece) ->
            Keeper(k.first, k.second, k.third, piece.checkKey(), time, lastOkAt = if (k.first in used) time else 0)
        }
        pieces.forEach { it.wipe() }
        val wrapped = wrapOwner(setId, points)
        runCatching { contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        store.update {
            BackupSet(
                setId = setId,
                createdAt = time,
                ownerPoints = wrapped,
                keepers = list,
                usedX = list.map { it.x }.toSet(),
                // Recorded so the file can be checked; "Back up now" saves a fresh one.
                file = SavedFile(uri.toString(), sha256(file), time, emptySet(), lastOkAt = time),
            )
        }
        BackupReminderWorker.schedule(this)
        note(true, "This phone now looks after the backup and its ${list.size} keeper(s). Check them, then Back up now.")
    }

    // ---- keeping pieces for others ---------------------------------------------------------------------

    private fun keepForSomeone() = session {
        val owner = ask(
            "Whose piece is this?",
            "Keep a piece only for someone you know, who is next to you. Alone it opens nothing.",
            "Their name",
        ) ?: cancelled()
        val bytes = QrLink.receiveOne(
            QrLink.KEEP,
            ::track,
            show = { qr, _ ->
                phase.value = Phase.ShowingQr(
                    qr,
                    "Let $owner scan this",
                    "On $owner's phone: Passkey Vault → ⋮ → Backup & recovery → Add a keeper → Person's phone. Both phones on the same Wi-Fi or hotspot.",
                )
            },
            ignored = { note(false, it) },
        )
        val share = try {
            RecoveryShare.parse(JSONObject(String(bytes)).getString("share"))
        } finally {
            bytes.fill(0)
        }
        try {
            val held = HeldShare(Base64Url.encode(share.setId), share.x, owner.take(BackupSetJson.LABEL_MAX), HeldShareCipher.seal(share), now())
            store.updateHeld { list -> list.filterNot { it.setId == held.setId && it.x == held.x } + held }
        } finally {
            share.wipe()
        }
        note(true, "You now keep a piece of $owner's backup key. Alone it opens nothing. Give it back only to $owner, in person.")
    }

    private fun answerCheck() = session {
        val message = ask("Answer a check", "Paste the whole message with the check (it contains ${ShareCheck.CHALLENGE_PREFIX}).", "Message")
            ?: cancelled()
        val challenge = ShareCheck.parseChallenge(message)
        val held = store.held.value.firstOrNull { it.setId == Base64Url.encode(challenge.setId) && it.x == challenge.x }
            ?: throw IllegalStateException("You don't keep the piece this check asks about. Tell its owner.")
        val share = HeldShareCipher.open(held)
        val answer = try {
            ShareCheck.answer(share, challenge)
        } finally {
            share.wipe()
        }
        store.updateHeld { list -> list.map { if (it == held) it.copy(lastAnsweredAt = now()) else it } }
        val done = CompletableDeferred<Unit>()
        phase.value = Phase.ShowCode(
            "Send this answer to ${held.owner}",
            "It proves you still have the piece, without revealing it.",
            answer,
            "Passkey Vault answer: $answer",
        )
        done.await() // until the person taps Done (stop() cancels the session)
    }

    private fun giveBack(held: HeldShare) = session {
        if (!yesNo(
                "Give back ${held.owner}'s piece?",
                "Only to ${held.owner}'s own phone, in front of you: whoever shows the QR code gets the piece. If someone " +
                    "else asks for it, by message or call, say no.",
                "Scan their QR code",
            )
        ) cancelled()
        if (!verifyUser("Give back a key piece", "To ${held.owner}'s phone")) cancelled()
        val share = HeldShareCipher.open(held)
        val data = JSONObject().put("share", share.text()).toString().toByteArray()
        try {
            phase.value = Phase.Busy("Scan the QR code on ${held.owner}'s phone")
            QrLink.sendOne(this, QrLink.RETURN, data, ::track)
        } finally {
            data.fill(0)
            share.wipe()
        }
        store.updateHeld { list -> list.map { if (it == held) it.copy(lastReturnedAt = now()) else it } }
        note(true, "Gave the piece to ${held.owner}'s phone. You still keep your copy.")
    }

    private fun deleteHeld(held: HeldShare) = session {
        if (!yesNo("Delete ${held.owner}'s piece?", "Tell ${held.owner}, so they can choose another keeper.", "Delete")) cancelled()
        store.updateHeld { list -> list - held }
        note(true, "Deleted ${held.owner}'s piece.")
    }

    // ---- screen ----------------------------------------------------------------------------------------

    @Composable
    private fun Screen() {
        val set by store.set.collectAsState()
        val held by store.held.collectAsState()
        val passkeys by PasskeyStore.get(this).passkeys.collectAsState()
        val movable = passkeys.filter { it.movable && it.wrappedKey.isNotEmpty() }
        val current = phase.value
        Column(
            Modifier
                .fillMaxSize()
                .systemBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Backup & recovery", style = MaterialTheme.typography.headlineSmall)
            when (current) {
                Phase.Idle -> Overview(set, held, movable.map { it.credentialId }.toSet(), movable.size, passkeys.size)
                is Phase.Busy -> Section(current.what) { OutlinedButton(onClick = ::stop) { Text("Cancel") } }
                is Phase.ShowingQr -> Section(current.title) {
                    Image(
                        bitmap = current.qr.asImageBitmap(),
                        contentDescription = "QR code with this phone's address and a one-time secret",
                        modifier = Modifier.size(260.dp).align(Alignment.CenterHorizontally),
                    )
                    Text(current.hint, style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = ::stop) { Text("Cancel") }
                }
                is Phase.AskText -> Section(current.title) {
                    val typed = remember(current) { mutableStateOf("") }
                    Text(current.hint)
                    OutlinedTextField(
                        value = typed.value,
                        onValueChange = { typed.value = it },
                        label = { Text(current.label) },
                        // The password keyboard doesn't learn or suggest what is typed.
                        keyboardOptions = if (current.secret) KeyboardOptions(keyboardType = KeyboardType.Password) else KeyboardOptions.Default,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { current.answer.complete(typed.value) }, enabled = typed.value.isNotBlank()) { Text("OK") }
                        OutlinedButton(onClick = { current.answer.complete(null) }) { Text("Cancel") }
                    }
                }
                is Phase.AskYesNo -> Section(current.title) {
                    Text(current.text)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { current.answer.complete(true) }) { Text(current.yes) }
                        OutlinedButton(onClick = { current.answer.complete(false) }) { Text(current.no) }
                    }
                }
                is Phase.ShowCode -> Section(current.title) {
                    Text(current.text)
                    Text(current.code, style = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { shareText(current.shareText) }) { Text("Send") }
                        OutlinedButton(onClick = ::stop) { Text("Done") }
                    }
                }
                is Phase.Confirm -> Section("Add these passkeys?") {
                    current.passkeys.forEach { Text("• $it") }
                    if (current.skipped > 0) {
                        Text("${current.skipped} more already on this phone; they stay as they are.", style = MaterialTheme.typography.bodySmall)
                    }
                    Text("Only add them if this is your own backup.", style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { current.answer.complete(true) }, enabled = current.passkeys.isNotEmpty()) { Text("Add") }
                        OutlinedButton(onClick = { current.answer.complete(false) }) { Text("Don't add") }
                    }
                }
                is Phase.Collect -> Section("Restore: ${current.have.size} of ${RecoveryShare.THRESHOLD} pieces") {
                    if (current.have.isNotEmpty()) Text("Have: " + current.have.joinToString())
                    Text("Get a piece from any keeper:")
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (!current.googleTried) Button(onClick = { current.answer.complete(Source.GOOGLE) }) { Text("From Google") }
                        Button(onClick = { current.answer.complete(Source.CARD_SCAN) }) { Text("Scan a card") }
                        OutlinedButton(onClick = { current.answer.complete(Source.CARD_TYPE) }) { Text("Type a card") }
                        Button(onClick = { current.answer.complete(Source.PERSON) }) { Text("From a person's phone") }
                    }
                    Text(
                        "Google's piece is there only if this phone was set up from your Google backup.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = { current.answer.complete(null) }) { Text("Cancel") }
                }
            }

            if (log.isNotEmpty()) {
                Section("Results") {
                    log.forEach {
                        Text(it.text, style = MaterialTheme.typography.bodySmall, color = if (it.ok) Color.Unspecified else MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }

    @Composable
    private fun Overview(set: BackupSet?, held: List<HeldShare>, movableIds: Set<String>, movableCount: Int, total: Int) {
        if (set == null) {
            Section("Back up your passkeys") {
                Text(
                    "Your movable passkeys go into one encrypted file, kept wherever you like (Google Drive, another " +
                        "cloud app, the phone). Its key is never shown to you: it's split into pieces given to keepers " +
                        "(Google, a printed card, someone you trust). Any two pieces open the backup; one alone opens " +
                        "nothing. The app checks now and then that every keeper still has its piece.",
                )
                Text(
                    "$movableCount of $total passkey(s) can be backed up. Only passkeys made as \"Can be moved\" (⋮ → Move " +
                        "passkeys) can be; the others never leave this phone.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Button(onClick = ::setUp, enabled = MovablePasskeys.fingerprintReady(this@BackupActivity)) { Text("Set up backup") }
                if (!MovablePasskeys.fingerprintReady(this@BackupActivity)) {
                    Text("Needs a fingerprint on this phone.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        } else {
            val time = now()
            val report = BackupHealth.report(set, movableIds, time)
            val (title, color) = when (report.level) {
                BackupHealth.Level.OK -> "Backup is healthy" to MaterialTheme.colorScheme.primaryContainer
                BackupHealth.Level.DUE -> "Backup needs a look" to MaterialTheme.colorScheme.tertiaryContainer
                BackupHealth.Level.PROBLEM -> "Backup can't restore right now" to MaterialTheme.colorScheme.errorContainer
            }
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = color)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(title, style = MaterialTheme.typography.titleMedium)
                    val working = set.keepers.count { BackupHealth.keeper(it, time) != BackupHealth.Level.PROBLEM }
                    Text("$working of ${set.keepers.size} keeper(s) can be counted on; restoring needs ${RecoveryShare.THRESHOLD}.")
                    report.messages.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                }
            }

            Section("Backup file") {
                val file = set.file
                Text(
                    if (file == null) {
                        "Not saved yet."
                    } else {
                        "Saved ${day(file.writtenAt)} with ${file.passkeyIds.size} passkey(s)" +
                            (if (file.lastOkAt > file.writtenAt) "; checked ${day(file.lastOkAt)}" else "") + "."
                    },
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { backUpNow(newPlace = false) }, enabled = movableCount > 0) { Text("Back up now") }
                    if (file != null) {
                        OutlinedButton(onClick = ::checkFile) { Text("Check file") }
                        TextButton(onClick = { backUpNow(newPlace = true) }, enabled = movableCount > 0) { Text("Save somewhere else") }
                    }
                }
            }

            Section("Keepers") {
                if (set.keepers.isEmpty()) Text("No keepers yet. Add at least ${RecoveryShare.THRESHOLD}; ${BackupHealth.RECOMMENDED_KEEPERS} is safer.")
                set.keepers.forEach { keeper -> KeeperRow(keeper, time) }
                Text("Add a keeper:", style = MaterialTheme.typography.titleSmall)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (set.keepers.none { it.kind == KeeperKind.GOOGLE }) OutlinedButton(onClick = ::addGoogle) { Text("Google") }
                    OutlinedButton(onClick = ::addCard) { Text("Printed card") }
                    OutlinedButton(onClick = ::addPerson) { Text("Person's phone") }
                }
                Text(
                    "Any two keepers together can restore your passkeys, so choose keepers who wouldn't team up against " +
                        "you, and keep the card away from Google Photos and Drive.",
                    style = MaterialTheme.typography.bodySmall,
                )
                TextButton(onClick = ::startOver) { Text("Start over with a new key") }
            }
        }

        Section("Restore a backup") {
            Text("On a new phone, or after losing passkeys: choose the backup file, then get pieces from any two keepers.")
            OutlinedButton(onClick = ::restore) { Text("Restore") }
        }

        Section("Keeping pieces for others") {
            Text(
                "Keep a piece of someone else's backup key: alone it opens nothing. They may ask you now and then to " +
                    "answer a check, and to give it back when they get a new phone.",
            )
            held.forEach { h ->
                Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Text("${h.owner} · piece ${h.x}", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "Kept since ${day(h.receivedAt)}" +
                            (if (h.lastAnsweredAt > 0) "; last check ${day(h.lastAnsweredAt)}" else "") +
                            (if (h.lastReturnedAt > 0) "; given back ${day(h.lastReturnedAt)}" else ""),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { giveBack(h) }) { Text("Give back") }
                        TextButton(onClick = { deleteHeld(h) }) { Text("Delete") }
                    }
                }
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = ::keepForSomeone) { Text("Keep a piece for someone") }
                if (held.isNotEmpty()) OutlinedButton(onClick = ::answerCheck) { Text("Answer a check") }
            }
        }
    }

    @Composable
    private fun KeeperRow(keeper: Keeper, time: Long) {
        val level = BackupHealth.keeper(keeper, time)
        Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            Text(
                "${keeper.label} · " + when (keeper.kind) {
                    KeeperKind.GOOGLE -> "Google backup"
                    KeeperKind.CARD -> "paper card"
                    KeeperKind.PERSON -> "their Passkey Vault"
                },
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                when (level) {
                    BackupHealth.Level.OK -> "OK, checked ${day(keeper.lastOkAt)}"
                    BackupHealth.Level.DUE -> if (keeper.lastOkAt == 0L) "Not checked from this phone yet" else "Check due (last ${day(keeper.lastOkAt)})"
                    BackupHealth.Level.PROBLEM -> "Problem: ${keeper.lastProblem}"
                } + if (keeper.pendingChallenge.isNotBlank()) " · waiting for their answer" else "",
                style = MaterialTheme.typography.bodySmall,
                color = if (level == BackupHealth.Level.PROBLEM) MaterialTheme.colorScheme.error else Color.Unspecified,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { check(keeper) }) {
                    Text(
                        when (keeper.kind) {
                            KeeperKind.GOOGLE -> "Check"
                            KeeperKind.CARD -> "Scan to check"
                            KeeperKind.PERSON -> if (keeper.pendingChallenge.isBlank()) "Send check" else "Send again"
                        },
                    )
                }
                if (keeper.kind == KeeperKind.PERSON && keeper.pendingChallenge.isNotBlank()) {
                    Button(onClick = { enterAnswer(keeper) }) { Text("Paste answer") }
                }
                TextButton(onClick = { removeKeeper(keeper) }) { Text("Remove") }
            }
        }
    }

    @Composable
    private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                content()
            }
        }
    }
}
