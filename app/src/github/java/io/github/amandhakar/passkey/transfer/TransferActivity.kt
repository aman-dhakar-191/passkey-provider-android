package io.github.amandhakar.passkey.transfer

import android.graphics.Bitmap
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.provider.verifyUser
import io.github.amandhakar.passkey.ui.PasskeyTheme
import io.github.amandhakar.passkey.webauthn.Base64Url
import io.github.amandhakar.securechannel.Connection
import io.github.amandhakar.securechannel.Handshake
import io.github.amandhakar.securechannel.Invite
import io.github.amandhakar.securechannel.LocalNetwork
import io.github.amandhakar.securechannel.Suites
import io.github.amandhakar.securechannel.TcpTransport
import io.github.amandhakar.securechannel.Transfer
import kotlinx.coroutines.CancellationException
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
    }

    private class LogLine(val ok: Boolean, val text: String)

    private val phase = mutableStateOf<Phase>(Phase.Idle)
    private val log = mutableStateListOf<LogLine>()
    private val newMovable = mutableStateOf(false)
    private var job: Job? = null
    private val open = mutableListOf<Closeable>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        newMovable.value = MovablePasskeys.newPasskeysMovable(this)
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

        if (!verifyUser("Send passkeys", "${movable.size} passkey(s) to your new phone")) {
            throw IllegalStateException("Cancelled")
        }
        phase.value = Phase.Busy("Sending ${movable.size} passkey(s)…")
        val payload = withContext(Dispatchers.Default) {
            TransferPayload.encode(
                movable.map { passkey ->
                    val id = Base64Url.decode(passkey.credentialId)
                    val publicKey = PasskeyKeys.publicKey(id) ?: throw IllegalStateException("A passkey's key is missing")
                    MovingPasskey(passkey, publicKey.encoded, MovablePasskeys.privateKey(passkey))
                },
            )
        }
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
            "Sent ${movable.size} passkey(s). This phone keeps its copies; delete them here once the new phone signs in.",
        )
    }

    /** New phone: show the QR code, receive one old phone's passkeys, add them. */
    private fun receive() = session {
        val listener = withContext(Dispatchers.IO) { TcpTransport.TcpListener(port = 0) }.tracked()
        val targets = LocalNetwork.inviteTargets(listener.port)
        if (targets.isEmpty()) throw IOException("No Wi-Fi address. Connect both phones to the same Wi-Fi or hotspot.")
        val secret = ByteArray(Handshake.QR_SECRET_SIZE).also { SecureRandom().nextBytes(it) }
        val qr = withContext(Dispatchers.Default) { QrCode.bitmap(Invite(Invite.TCP, targets, secret).encode(QR_PREFIX)) }
        phase.value = Phase.ShowingQr(qr, targets)

        val connection = withContext(Dispatchers.IO) { listener.accept() }.tracked()
        listener.close() // one old phone per QR code
        phase.value = Phase.Busy("Connecting…")
        val pending = withContext(Dispatchers.IO) {
            Handshake.respond(connection, { id -> Suites.software.firstOrNull { it.id == id } }, secret)
        }
        if (!pending.usesQrSecret) {
            pending.close()
            throw SecurityException("The other phone didn't use this QR code; nothing received")
        }
        val channel = withContext(Dispatchers.IO) { pending.confirm(true) }.tracked()
        phase.value = Phase.Busy("Receiving passkeys…")
        val received = mutableListOf<ByteArrayOutputStream>()
        withContext(Dispatchers.IO) {
            Transfer.receiveAll(channel, MAX_PAYLOAD_BYTES, { _, _ -> ByteArrayOutputStream().also { received += it } }) {}
        }
        val (added, skipped) = withContext(Dispatchers.Default) {
            var added = 0
            var skipped = 0
            received.forEach { sink ->
                val bytes = sink.toByteArray()
                try {
                    val (a, s) = addAll(bytes)
                    added += a
                    skipped += s
                } finally {
                    bytes.fill(0)
                }
            }
            added to skipped
        }
        note(
            true,
            "Received: $added passkey(s) added" + if (skipped > 0) ", $skipped already on this phone (skipped)" else "",
        )
    }

    /** Adds received passkeys, skipping any this phone already has. Returns (added, skipped). */
    private fun addAll(bytes: ByteArray): Pair<Int, Int> {
        val store = PasskeyStore.get(this)
        var added = 0
        var skipped = 0
        TransferPayload.decode(bytes).forEach { moving ->
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
                        "that only opens with your fingerprint or screen lock, for moving it. Sites can see that it " +
                        "can be backed up.",
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
                is Phase.Busy -> Section(current.what) {
                    OutlinedButton(onClick = ::stop) { Text("Cancel") }
                }
                Phase.Idle -> {
                    Section("Send to a new phone") {
                        Text(
                            "$movableCount movable passkey(s) on this phone" +
                                if (passkeys.size > movableCount) " (${passkeys.size - movableCount} stay here)." else ".",
                        )
                        Button(onClick = ::send, enabled = movableCount > 0) { Text("Scan the new phone's QR code") }
                    }
                    Section("Receive from your old phone") {
                        Text("Shows a QR code for the old phone to scan. Both phones on the same Wi-Fi or hotspot.")
                        Button(onClick = ::receive) { Text("Show QR code") }
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

    private fun setMovable(movable: Boolean) {
        MovablePasskeys.setNewPasskeysMovable(this, movable)
        newMovable.value = movable
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
