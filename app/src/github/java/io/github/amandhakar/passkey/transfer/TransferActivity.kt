package io.github.amandhakar.passkey.transfer

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.provider.verifyWithFingerprint
import io.github.amandhakar.passkey.ui.PasskeyTheme
import io.github.amandhakar.passkey.webauthn.Base64Url
import io.github.amandhakar.securechannel.Connection
import io.github.amandhakar.securechannel.Handshake
import io.github.amandhakar.securechannel.Invite
import io.github.amandhakar.securechannel.LocalNetwork
import io.github.amandhakar.securechannel.QrReceiver
import io.github.amandhakar.securechannel.Suites
import io.github.amandhakar.securechannel.TcpTransport
import io.github.amandhakar.securechannel.Transfer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.security.SecureRandom
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Moving passkeys to a new phone (GitHub build). The new phone shows a QR code with its Wi-Fi address and a
 * one-time secret; the old phone scans it and sends its movable passkeys over the secure channel (shared with
 * Crypto Lab, see the securechannel module), which the secret authenticates: a phone that never saw the QR
 * code can't connect. The old phone keeps its copies; delete them there once the new phone works.
 */
class TransferActivity : FragmentActivity() {
    private sealed interface Phase {
        data object Idle : Phase
        data class Busy(val what: String) : Phase
        class ShowingQr(val qr: Bitmap, val addresses: List<String>) : Phase

        /** New phone: the passkeys that arrived, waiting for the person to add them or not. */
        class Confirm(
            val passkeys: List<String>,
            val skipped: Int,
            val answer: CompletableDeferred<Boolean>,
            val hint: String,
        ) : Phase

        /** Backup: the recovery key, shown once. The file is written only after the person says they saved it. */
        class ShowKey(val text: String, val answer: CompletableDeferred<Boolean>) : Phase

        /** Restore: waiting for the recovery key to be typed or pasted (null = cancelled). */
        class AskKey(val answer: CompletableDeferred<String?>) : Phase
    }

    private class LogLine(val ok: Boolean, val text: String)

    private val phase = mutableStateOf<Phase>(Phase.Idle)
    private val log = mutableStateListOf<LogLine>()
    private val newMovable = mutableStateOf(false)
    private var job: Job? = null
    private val open = mutableListOf<Closeable>()

    // The system file picker, so the person chooses where a backup goes (Google Drive, another cloud app, local
    // storage): this app needs no storage permission, no Google account and no network for it.
    private var picked: CompletableDeferred<Uri?>? = null
    private val createFile = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { picked?.complete(it) }
    private val openFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { picked?.complete(it) }

    private suspend fun pick(launch: () -> Unit): Uri? {
        val result = CompletableDeferred<Uri?>()
        picked = result
        launch()
        return result.await()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The QR code holds the one-time secret: keep it out of screenshots, screen recordings and Recents.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        newMovable.value = MovablePasskeys.newPasskeysMovableSetting(this)
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

    private fun note(ok: Boolean, text: String) {
        runOnUiThread { log.add(0, LogLine(ok, text)) }
        ProviderErrors.note(this, "Move passkeys: $text")
    }

    private fun stop() {
        synchronized(open) {
            open.forEach { runCatching { it.close() } }
            open.clear()
        }
        job?.cancel()
        job = null
        (phase.value as? Phase.Confirm)?.answer?.complete(false)
        (phase.value as? Phase.ShowKey)?.answer?.complete(false)
        (phase.value as? Phase.AskKey)?.answer?.complete(null)
        picked?.complete(null)
        phase.value = Phase.Idle
    }

    private fun <T : Closeable> T.tracked(): T = also { synchronized(open) { open += it } }

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

    /** Old phone: scan the new phone's QR code, confirm with fingerprint or screen lock, send. */
    private fun send() = session {
        val store = PasskeyStore.get(this)
        val movable = store.all().filter { it.movable && it.wrappedKey.isNotEmpty() }
        if (!MovablePasskeys.fingerprintReady(this)) {
            note(false, "Sending passkeys needs a fingerprint; the screen lock alone isn't enough. Set one up in Settings.")
            return@session
        }
        if (movable.isEmpty()) {
            note(false, "No movable passkeys on this phone. Passkeys made before you chose \"Can be moved\" stay here.")
            return@session
        }
        phase.value = Phase.Busy("Scan the QR code on the new phone")
        val invite = Invite.parse(scanQr(), QR_PREFIX)
        require(invite.transport == Invite.TCP) { "Unsupported QR code" }
        phase.value = Phase.Busy("Connecting…")
        val connection = withContext(Dispatchers.IO) { firstReachable(invite.targets) }.tracked()
        val pending = withContext(Dispatchers.IO) { Handshake.initiate(connection, Suites.software.first(), invite.secret) }
        val channel = withContext(Dispatchers.IO) { pending.confirm(true) }.tracked()
        note(true, "Connected to the new phone; the QR code's secret checked out")

        // Fingerprint only: someone who saw the PIN typed must not be able to copy passkeys away.
        if (!verifyWithFingerprint("Send passkeys", "${movable.size} passkey(s) to the phone whose QR code you scanned")) {
            throw IllegalStateException("Cancelled")
        }
        phase.value = Phase.Busy("Sending ${movable.size} passkey(s)…")
        val payload = withContext(Dispatchers.Default) { encodeMovable(movable) }
        try {
            withContext(Dispatchers.IO) {
                Transfer.send(channel, "passkeys.json", payload.size.toLong(), payload.inputStream())
                Transfer.finish(channel)
            }
        } finally {
            payload.fill(0)
        }
        store.markBackedUp(movable.map { it.credentialId }.toSet())
        note(
            true,
            "Sent ${movable.size} passkey(s); the new phone shows them and asks before adding. This phone keeps its " +
                "copies; delete them here once the new phone signs in.",
        )
    }

    /** New phone: show the QR code, receive one old phone's passkeys, add them. */
    private fun receive() = session {
        // The received copies go under the fingerprint-only vault, which needs a fingerprint enrolled.
        if (!MovablePasskeys.fingerprintReady(this)) {
            throw IllegalStateException("Receiving passkeys needs a fingerprint on this phone. Set one up in Settings first.")
        }
        val listener = withContext(Dispatchers.IO) { TcpTransport.TcpListener(port = 0) }.tracked()
        val targets = LocalNetwork.inviteTargets(listener.port)
        if (targets.isEmpty()) throw IOException("No Wi-Fi address. Connect both phones to the same Wi-Fi or hotspot.")
        val secret = ByteArray(Handshake.QR_SECRET_SIZE).also { SecureRandom().nextBytes(it) }
        val qr = withContext(Dispatchers.Default) { QrCode.bitmap(Invite(Invite.TCP, targets, secret).encode(QR_PREFIX)) }
        phase.value = Phase.ShowingQr(qr, targets)

        // Keeps listening past strangers on the network: only a phone with this QR code's secret gets through.
        val channel = withContext(Dispatchers.IO) {
            QrReceiver.accept(listener, { id -> Suites.software.firstOrNull { it.id == id } }, secret) { peer, reason ->
                note(false, "Ignored a connection from $peer (${reason.message ?: reason.javaClass.simpleName})")
            }
        }.tracked()
        listener.close() // one old phone per QR code
        phase.value = Phase.Busy("Receiving passkeys…")
        val received = ByteArrayOutputStream()
        withContext(Dispatchers.IO) {
            // The old phone sends exactly one item, at most MAX_PAYLOAD_BYTES.
            Transfer.receiveAll(channel, MAX_PAYLOAD_BYTES, { _, _ -> received }, maxItems = 1) {}
        }
        importPayload(received.toByteArray(), "Only add them if they came from your own old phone.")
    }

    /**
     * Checks a payload that arrived (from the old phone or out of a backup), shows which accounts it holds, and
     * adds the new ones if the person says so. Wipes the bytes and every private key before returning.
     */
    private suspend fun importPayload(bytes: ByteArray, hint: String) {
        var incoming = emptyList<MovingPasskey>()
        try {
            incoming = withContext(Dispatchers.Default) { TransferPayload.decode(bytes) }
            val store = PasskeyStore.get(this)
            val (new, already) = incoming.partition { moving ->
                store.all().none {
                    it.credentialId == moving.passkey.credentialId ||
                        (it.rpId == moving.passkey.rpId && it.userId == moving.passkey.userId)
                }
            }
            // The person decides: they see exactly which accounts arrive before anything is added.
            val answer = CompletableDeferred<Boolean>()
            phase.value = Phase.Confirm(
                new.map { "${it.passkey.userName.ifBlank { it.passkey.displayName }} on ${it.passkey.rpId}" },
                already.size,
                answer,
                hint,
            )
            if (new.isEmpty() || !answer.await()) {
                note(true, "Nothing added" + if (already.isNotEmpty()) " (${already.size} already on this phone)" else "")
                return
            }
            phase.value = Phase.Busy("Adding passkeys…")
            val (added, skipped) = withContext(Dispatchers.Default) { addAll(new) }
            note(
                true,
                "Received: $added passkey(s) added" +
                    (already.size + skipped).let { if (it > 0) ", $it already on this phone (skipped)" else "" },
            )
        } finally {
            // Added, declined or skipped: no private key stays readable in this array.
            incoming.forEach { it.privateKey.fill(0) }
            bytes.fill(0)
        }
    }

    /** The movable passkeys with their private keys, as a [TransferPayload]. Call within 30 s of a fingerprint check. */
    private fun encodeMovable(movable: List<Passkey>): ByteArray =
        TransferPayload.encode(
            movable.map { passkey ->
                val id = Base64Url.decode(passkey.credentialId)
                val publicKey = PasskeyKeys.publicKey(id) ?: throw IllegalStateException("A passkey's key is missing")
                MovingPasskey(passkey, publicKey.encoded, MovablePasskeys.privateKey(this@TransferActivity, passkey))
            },
        )

    /**
     * Writes an encrypted backup of the movable passkeys. The recovery key is shown first, and the file is
     * written (where the person chooses) only after they confirm they saved it.
     */
    private fun backup() = session {
        val store = PasskeyStore.get(this)
        val movable = store.all().filter { it.movable && it.wrappedKey.isNotEmpty() }
        if (!MovablePasskeys.fingerprintReady(this)) {
            note(false, "Backing up passkeys needs a fingerprint; the screen lock alone isn't enough. Set one up in Settings.")
            return@session
        }
        if (movable.isEmpty()) {
            note(false, "No movable passkeys on this phone. Passkeys made before you chose \"Can be moved\" stay here.")
            return@session
        }
        phase.value = Phase.Busy("Confirm with your fingerprint")
        if (!verifyWithFingerprint("Back up passkeys", "${movable.size} passkey(s) into an encrypted file")) {
            throw IllegalStateException("Cancelled")
        }
        phase.value = Phase.Busy("Encrypting ${movable.size} passkey(s)…")
        val key = BackupFile.newRecoveryKey()
        val file = withContext(Dispatchers.Default) {
            val payload = encodeMovable(movable)
            try {
                BackupFile.seal(payload, key)
            } finally {
                payload.fill(0)
            }
        }
        val recoveryText = BackupFile.recoveryText(key)
        key.fill(0)

        val saved = CompletableDeferred<Boolean>()
        phase.value = Phase.ShowKey(recoveryText, saved)
        if (!saved.await()) {
            note(true, "Backup cancelled; no file was written")
            return@session
        }
        phase.value = Phase.Busy("Choose where to save the backup")
        val uri = pick { createFile.launch("passkey-vault-backup-${java.time.LocalDate.now()}.pvbackup") }
        if (uri == null) {
            note(true, "Backup cancelled; no file was written")
            return@session
        }
        withContext(Dispatchers.IO) {
            val out = contentResolver.openOutputStream(uri, "wt") ?: throw IOException("Couldn't write to that location")
            out.use { it.write(file) }
        }
        store.markBackedUp(movable.map { it.credentialId }.toSet())
        note(
            true,
            "Saved an encrypted backup of ${movable.size} passkey(s). It opens only with the recovery key you were " +
                "shown; without that key nobody can read it, including this app.",
        )
    }

    /** Reads a backup file, asks for its recovery key, and offers to add the passkeys inside. */
    private fun restore() = session {
        // The restored copies go under the fingerprint-only vault, which needs a fingerprint enrolled.
        if (!MovablePasskeys.fingerprintReady(this)) {
            throw IllegalStateException("Restoring passkeys needs a fingerprint on this phone. Set one up in Settings first.")
        }
        phase.value = Phase.Busy("Choose the backup file")
        val uri = pick { openFile.launch(arrayOf("*/*")) }
        if (uri == null) {
            note(true, "Nothing chosen")
            return@session
        }
        val file = withContext(Dispatchers.IO) {
            // One byte more than the biggest real backup, so an oversized file is refused without reading it all.
            val input = contentResolver.openInputStream(uri) ?: throw IOException("Couldn't read that file")
            input.use { it.readNBytes(BackupFile.MAX_FILE_BYTES.toInt() + 1) }
        }
        val asked = CompletableDeferred<String?>()
        phase.value = Phase.AskKey(asked)
        val typed = asked.await()
        if (typed == null) {
            note(true, "Restore cancelled")
            return@session
        }
        phase.value = Phase.Busy("Decrypting…")
        val bytes = withContext(Dispatchers.Default) {
            val key = BackupFile.parseRecoveryText(typed)
            try {
                BackupFile.open(file, key)
            } finally {
                key.fill(0)
            }
        }
        importPayload(bytes, "Only add them if this is your own backup.")
    }

    /** Adds received passkeys, skipping any this phone already has. Returns (added, skipped). */
    private fun addAll(incoming: List<MovingPasskey>): Pair<Int, Int> {
        val store = PasskeyStore.get(this)
        var added = 0
        var skipped = 0
        incoming.forEach { moving ->
            val passkey = moving.passkey
            val exists = store.all().any {
                it.credentialId == passkey.credentialId || (it.rpId == passkey.rpId && it.userId == passkey.userId)
            }
            if (exists) {
                skipped++
                return@forEach
            }
            val (publicKey, privateKey) = TransferPayload.keyPair(moving)
            val id = Base64Url.decode(passkey.credentialId)
            val wrapped = MovablePasskeys.importKey(id, publicKey, privateKey)
            moving.privateKey.fill(0)
            if (store.addIfAbsent(passkey.copy(movable = true, backedUp = true, wrappedKey = wrapped))) {
                added++
            } else {
                PasskeyKeys.delete(id)
                skipped++
            }
        }
        return added to skipped
    }

    /** The QR code lists every Wi-Fi/hotspot address of the new phone; use the first that answers. */
    private fun firstReachable(targets: List<String>): Connection {
        val failures = mutableListOf<String>()
        for (target in targets) {
            val host = target.substringBefore(':')
            val port = target.substringAfter(':', "").toIntOrNull() ?: continue
            try {
                return TcpTransport.connect(host, port, timeoutMs = 4_000)
            } catch (e: IOException) {
                failures += "$target (${e.javaClass.simpleName})"
            }
        }
        throw IOException("Couldn't reach the new phone (${failures.joinToString()}). Are both phones on the same Wi-Fi?")
    }

    private suspend fun scanQr(): String = suspendCancellableCoroutine { cont ->
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(this, options).startScan()
            .addOnSuccessListener { if (cont.isActive) cont.resume(it.rawValue.orEmpty()) }
            .addOnCanceledListener { if (cont.isActive) cont.resumeWithException(IllegalStateException("Cancelled")) }
            .addOnFailureListener { if (cont.isActive) cont.resumeWithException(IllegalStateException("QR scanner: ${it.message}")) }
    }

    @Composable
    private fun Screen() {
        val passkeys by PasskeyStore.get(this).passkeys.collectAsState()
        val movableCount = passkeys.count { it.movable }
        val current = phase.value
        Column(
            Modifier
                .fillMaxSize()
                .systemBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Move passkeys", style = MaterialTheme.typography.headlineSmall)

            Section("New passkeys") {
                Choice(
                    selected = !newMovable.value,
                    title = "Only on this phone (most secure)",
                    detail = "The key is made inside the phone's secure hardware and can never leave it.",
                ) { setMovable(false) }
                Choice(
                    selected = newMovable.value,
                    title = "Can be moved to a new phone",
                    detail = "The key is made in the app and locked into the secure hardware, with an encrypted copy " +
                        "for moving it that opens only with your fingerprint, never the PIN. Needs a fingerprint; " +
                        "adding or removing a fingerprint later stops earlier passkeys from moving (they still " +
                        "sign in). Sites can see that it can be backed up.",
                ) { setMovable(true) }
                Text(
                    "Only affects passkeys made from now on. Existing passkeys keep how they were made.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            when (current) {
                is Phase.ShowingQr -> Section("Scan this with your old phone") {
                    Image(
                        bitmap = current.qr.asImageBitmap(),
                        contentDescription = "QR code with this phone's address and a one-time secret",
                        modifier = Modifier.size(260.dp).align(Alignment.CenterHorizontally),
                    )
                    Text(
                        "On the old phone: Passkey Vault → ⋮ → Move passkeys → Send to a new phone. Both phones on the " +
                            "same Wi-Fi or hotspot. Don't show this code to anyone else.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = ::stop) { Text("Cancel") }
                }
                is Phase.Confirm -> Section("Add these passkeys?") {
                    current.passkeys.forEach { Text("• $it") }
                    if (current.skipped > 0) {
                        Text("${current.skipped} more already on this phone; they stay as they are.", style = MaterialTheme.typography.bodySmall)
                    }
                    Text(current.hint, style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { current.answer.complete(true) }, enabled = current.passkeys.isNotEmpty()) { Text("Add") }
                        OutlinedButton(onClick = { current.answer.complete(false) }) { Text("Don't add") }
                    }
                }
                is Phase.ShowKey -> Section("Your recovery key") {
                    Text(
                        "Save this key now, in a password manager or on paper. The backup can't be opened without " +
                            "it, by anyone, including this app, and it is shown only this once.",
                        color = MaterialTheme.colorScheme.error,
                    )
                    Text(
                        current.text.chunked(20).joinToString("\n"),
                        style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                    )
                    Text(
                        "Don't keep the key in the same place as the backup file: whoever has both can read your " +
                            "passkeys. Copying puts it on the clipboard until you copy something else.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { current.answer.complete(true) }) { Text("I saved it; choose where to save the file") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { copySecret(current.text) }) { Text("Copy") }
                        OutlinedButton(onClick = { current.answer.complete(false) }) { Text("Cancel") }
                    }
                }
                is Phase.AskKey -> Section("Recovery key") {
                    val typed = remember { mutableStateOf("") }
                    Text("Type or paste the recovery key that was shown when this backup was made.")
                    OutlinedTextField(
                        value = typed.value,
                        onValueChange = { typed.value = it },
                        label = { Text("Recovery key") },
                        // The password keyboard doesn't learn or suggest what is typed.
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { current.answer.complete(typed.value) }, enabled = typed.value.isNotBlank()) { Text("Open backup") }
                        OutlinedButton(onClick = { current.answer.complete(null) }) { Text("Cancel") }
                    }
                }
                is Phase.Busy -> Section(current.what) {
                    OutlinedButton(onClick = ::stop) { Text("Cancel") }
                }
                Phase.Idle -> {
                    Section("Send to a new phone") {
                        Text(
                            "$movableCount movable passkey(s) on this phone" +
                                if (passkeys.size > movableCount) " (${passkeys.size - movableCount} stay here)." else ".",
                        )
                        Text(
                            "Only scan a QR code shown on your own new phone, in front of you. Whoever shows the code " +
                                "gets the passkeys.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                        Button(onClick = ::send, enabled = movableCount > 0) { Text("Scan the new phone's QR code") }
                    }
                    Section("Receive from your old phone") {
                        Text("Shows a QR code for the old phone to scan. Both phones on the same Wi-Fi or hotspot.")
                        Button(onClick = ::receive) { Text("Show QR code") }
                    }
                    Section("Encrypted backup file") {
                        Text(
                            "Saves the $movableCount movable passkey(s) into one encrypted file, wherever you choose: " +
                                "Google Drive, another cloud app, or this phone. The file opens only with a recovery key " +
                                "shown once when you make it. Without that key nobody can read the file, including this " +
                                "app, so keep the key somewhere safe and apart from the file.",
                        )
                        Button(onClick = ::backup, enabled = movableCount > 0) { Text("Back up to a file") }
                        Text("Restore a backup made by Passkey Vault, on this phone or a new one.", style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(onClick = ::restore) { Text("Restore from a backup") }
                    }
                }
            }

            if (log.isNotEmpty()) {
                Section("Results") {
                    log.forEach {
                        Text(
                            it.text,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (it.ok) Color.Unspecified else MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }
    }

    /** Puts the recovery key on the clipboard, marked sensitive so Android hides it from the clipboard preview. */
    private fun copySecret(text: String) {
        val clip = ClipData.newPlainText("Recovery key", text)
        clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
    }

    /** Turning "Can be moved" on needs the owner's fingerprint; turning it off doesn't. */
    private fun setMovable(movable: Boolean) {
        if (!movable || newMovable.value) {
            MovablePasskeys.setNewPasskeysMovable(this, movable)
            newMovable.value = movable
            return
        }
        if (!MovablePasskeys.fingerprintReady(this)) {
            note(false, "Movable passkeys need a fingerprint; the screen lock alone isn't enough. Set one up in Settings.")
            return
        }
        lifecycleScope.launch {
            val ok = runCatching { verifyWithFingerprint("Make new passkeys movable", "They can then be copied to another phone") }
                .getOrElse { note(false, it.message ?: "Cannot verify"); false }
            if (ok) {
                MovablePasskeys.setNewPasskeysMovable(this@TransferActivity, true)
                newMovable.value = true
            }
        }
    }

    @Composable
    private fun Choice(selected: Boolean, title: String, detail: String, onSelect: () -> Unit) {
        Row(
            Modifier
                .fillMaxWidth()
                .selectable(selected = selected, onClick = onSelect)
                .padding(vertical = 4.dp),
        ) {
            RadioButton(selected = selected, onClick = null)
            Column(Modifier.padding(start = 8.dp)) {
                Text(title)
                Text(detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    @Composable
    private fun Section(title: String, content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                content()
            }
        }
    }

    private companion object {
        /** Passkey Vault's own QR codes; Crypto Lab's (and anything else) are refused. */
        const val QR_PREFIX = "passkeyvault-move:v1"
        const val MAX_PAYLOAD_BYTES = 4L * 1024 * 1024
    }
}
