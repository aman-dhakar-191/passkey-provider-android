package io.github.amandhakar.cryptolab.ui

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import io.github.amandhakar.cryptolab.android.LabSuites
import io.github.amandhakar.cryptolab.core.CipherSuite
import io.github.amandhakar.cryptolab.core.Handshake
import io.github.amandhakar.cryptolab.core.PendingChannel
import io.github.amandhakar.cryptolab.core.SecureChannel
import io.github.amandhakar.cryptolab.core.SelfTest
import io.github.amandhakar.cryptolab.core.Transfer
import io.github.amandhakar.cryptolab.transport.TcpTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.File
import java.io.InputStream
import java.net.Inet4Address
import java.net.NetworkInterface
import java.security.SecureRandom
import java.text.DateFormat
import java.util.Date
import kotlin.coroutines.cancellation.CancellationException

class MainActivity : ComponentActivity() {
    private class LogLine(val ok: Boolean, val text: String)

    /** What the screen is doing; only one session at a time. */
    private sealed interface Phase {
        data object Idle : Phase
        data class Busy(val what: String) : Phase
        /** [addresses]: (IP, network interface) pairs, the likely reachable ones first. */
        data class Listening(val addresses: List<Pair<String, String>>, val port: Int) : Phase
        class Compare(val pending: PendingChannel, val answer: CompletableDeferred<Boolean>) : Phase

        /** Receiver: a sender is connected; everything it sends is received until it disconnects. */
        data class Receiving(val peer: String, val sas: String, val received: Int) : Phase

        /** Sender: the code was confirmed; send as many items as you like over this one channel. */
        class Connected(val peer: String, val sas: String, val suite: String, val outbox: Channel<Payload>) : Phase
    }

    /** Something to send: a name, its size and a way to read it. */
    private class Payload(val name: String, val size: Long, val open: () -> InputStream)

    private val log = mutableStateListOf<LogLine>()
    private val suites = mutableStateListOf<Pair<CipherSuite, String?>>()
    private val selected = mutableIntStateOf(0)
    private val phase = mutableStateOf<Phase>(Phase.Idle)
    private var job: Job? = null
    private var listener: Closeable? = null
    private var openResource: Closeable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        lifecycleScope.launch {
            val checked = withContext(Dispatchers.IO) { LabSuites.all.map { it to it.supportProblem() } }
            suites.addAll(checked)
            selected.intValue = checked.indexOfFirst { it.second == null }.coerceAtLeast(0)
            checked.filter { it.second != null }.forEach { (suite, problem) ->
                note(false, "${suite.label} is not available on this phone: $problem")
            }
        }
        setContent {
            val context = LocalContext.current
            val colors = if (isSystemInDarkTheme()) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            MaterialTheme(colorScheme = colors) {
                Surface(Modifier.fillMaxSize()) { Screen() }
            }
        }
    }

    override fun onDestroy() {
        stop()
        super.onDestroy()
    }

    private fun note(ok: Boolean, text: String) {
        val stamped = LogLine(ok, "${DateFormat.getTimeInstance().format(Date())}  $text")
        runOnUiThread { log.add(0, stamped) }
    }

    private val selectedSuite: CipherSuite? get() = suites.getOrNull(selected.intValue)?.takeIf { it.second == null }?.first

    /** The receiver uses its selected suite when the ids match, else any working suite with that id. */
    private fun suiteFor(id: String): CipherSuite? =
        selectedSuite?.takeIf { it.id == id } ?: suites.firstOrNull { it.first.id == id && it.second == null }?.first

    private fun stop() {
        runCatching { listener?.close() }
        listener = null
        runCatching { openResource?.close() }
        openResource = null
        job?.cancel()
        job = null
        (phase.value as? Phase.Compare)?.answer?.complete(false)
        phase.value = Phase.Idle
    }

    private fun session(block: suspend () -> Unit) {
        if (phase.value != Phase.Idle) return
        phase.value = Phase.Busy("Starting…") // before launching, so a double tap can't start two sessions
        job = lifecycleScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Stop closes the sockets, which fails the blocked call; that's not worth reporting.
                if (isActive) note(false, "${e.javaClass.simpleName}: ${e.message}")
            } finally {
                runCatching { listener?.close() }
                listener = null
                runCatching { openResource?.close() }
                openResource = null
                phase.value = Phase.Idle
            }
        }
    }

    /** Shows the code and waits for this person to say whether it matches the other phone's. */
    private suspend fun compare(pending: PendingChannel): SecureChannel {
        openResource = pending
        note(true, "Key exchange done with ${pending.suite.label}, code ${pending.sas}, session ${pending.sessionId}")
        val answer = CompletableDeferred<Boolean>()
        phase.value = Phase.Compare(pending, answer)
        val match = answer.await()
        phase.value = Phase.Busy(if (match) "Waiting for the other phone to confirm…" else "Closing…")
        val channel = withContext(Dispatchers.IO) { pending.confirm(match) }
        openResource = channel
        note(true, "Both people confirmed the code; channel open")
        return channel
    }

    /** Listens until Stop: each sender connects, both people compare the code, then it sends any number of items. */
    private fun receive() = session {
        val server = withContext(Dispatchers.IO) { TcpTransport.Listener() }
        listener = server
        val addresses = localAddresses()
        val dir = File(cacheDir, "received").apply { mkdirs() }
        while (true) {
            phase.value = Phase.Listening(addresses, server.port)
            val connection = withContext(Dispatchers.IO) { server.accept() }
            openResource = connection
            val peer = connection.peer
            try {
                note(true, "Connection from $peer")
                phase.value = Phase.Busy("Key exchange with $peer…")
                val pending = withContext(Dispatchers.IO) { Handshake.respond(connection, ::suiteFor) }
                val channel = compare(pending)
                phase.value = Phase.Receiving(peer, pending.sas, 0)
                var file: File? = null
                val count = withContext(Dispatchers.IO) {
                    Transfer.receiveAll(
                        channel,
                        MAX_RECEIVE_BYTES,
                        { name, _ -> File(dir, safeName(name)).also { file = it }.outputStream() },
                    ) { result ->
                        val preview = file?.takeIf { it.length() <= PREVIEW_BYTES }?.readText()?.let { "\nText: $it" }.orEmpty()
                        note(true, "Received \"${result.name}\": ${result.bytes} bytes in ${result.millis} ms, SHA-256 ${result.sha256.take(16)}… matches$preview")
                        runOnUiThread { (phase.value as? Phase.Receiving)?.let { phase.value = it.copy(received = it.received + 1) } }
                    }
                }
                note(true, "$peer disconnected after $count item(s); still waiting for senders")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (!currentCoroutineContext().isActive) throw e
                // One failed sender (wrong code, dropped connection, ...) doesn't stop the receiver.
                note(false, "$peer: ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                runCatching { connection.close() }
                openResource = null
            }
        }
    }

    /** Connects and, once both people confirm the code, sends whatever is queued until Disconnect. */
    private fun connect(target: String) = session {
        val suite = selectedSuite ?: throw IllegalStateException("Choose a suite that works on this phone")
        // Pasted or typed addresses sometimes carry spaces ("100. 86.77.63").
        val address = target.filterNot { it.isWhitespace() }
        val host = address.substringBefore(':')
        val port = address.substringAfter(':', "").toIntOrNull() ?: TcpTransport.DEFAULT_PORT
        if (host.isEmpty()) throw IllegalArgumentException("Enter the other phone's address")
        phase.value = Phase.Busy("Connecting to $host:$port…")
        val connection = withContext(Dispatchers.IO) { TcpTransport.connect(host, port) }
        openResource = connection
        phase.value = Phase.Busy("Key exchange…")
        val pending = withContext(Dispatchers.IO) { Handshake.initiate(connection, suite) }
        val channel = compare(pending)
        val outbox = Channel<Payload>(Channel.UNLIMITED)
        val connected = Phase.Connected(connection.peer, pending.sas, suite.label, outbox)
        phase.value = connected
        for (payload in outbox) {
            phase.value = Phase.Busy("Sending ${payload.name}…")
            val result = withContext(Dispatchers.IO) { payload.open().use { Transfer.send(channel, payload.name, payload.size, it) } }
            note(
                true,
                "Sent \"${result.name}\": ${result.bytes} bytes in ${result.millis} ms " +
                    "(%.1f MB/s); the receiver confirmed SHA-256 ${result.sha256.take(16)}…".format(result.megabytesPerSecond),
            )
            phase.value = connected
        }
        withContext(Dispatchers.IO) { Transfer.finish(channel) }
        channel.close()
        note(true, "Disconnected from ${connection.peer}")
    }

    /** Queues [payload] on the connected session, if there is one. */
    private fun send(payload: Payload) {
        (phase.value as? Phase.Connected)?.outbox?.trySend(payload)
    }

    private fun selfTest() = session {
        phase.value = Phase.Busy("Self-test running…")
        val working = suites.filter { it.second == null }.map { it.first }
        withContext(Dispatchers.Default) {
            SelfTest.run(working) { note(it.ok, it.text) }
        }
        note(true, "Self-test finished")
    }

    private fun filePayload(uri: Uri): Payload {
        var name = "file"
        var size = -1L
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                name = c.getString(0) ?: name
                if (!c.isNull(1)) size = c.getLong(1)
            }
        }
        if (size < 0) throw IllegalStateException("The file's size is unknown")
        return Payload(name, size) { contentResolver.openInputStream(uri) ?: throw IllegalStateException("Cannot open the file") }
    }

    private fun randomPayload(bytes: Int): Payload {
        val data = ByteArray(bytes).also { SecureRandom().nextBytes(it) }
        return Payload("random-${bytes / 1_048_576}MB.bin", bytes.toLong()) { ByteArrayInputStream(data) }
    }

    @Composable
    private fun Screen() {
        var target by remember { mutableStateOf("") }
        var message by remember { mutableStateOf("Hello from Crypto Lab") }
        val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) {
                runCatching { filePayload(uri) }
                    .onSuccess { send(it) }
                    .onFailure { note(false, "${it.javaClass.simpleName}: ${it.message}") }
            }
        }
        val current = phase.value
        val idle = current == Phase.Idle

        Column(
            Modifier
                .fillMaxSize()
                .systemBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Crypto Lab", style = MaterialTheme.typography.headlineSmall)
            Text(
                "Try ways to encrypt data and send it to another phone. Key exchange plus authenticated " +
                    "encryption; compare the 6-digit code on both phones to rule out a man in the middle.",
                style = MaterialTheme.typography.bodyMedium,
            )

            Section("Approach (the sender's choice is used)") {
                suites.forEachIndexed { index, (suite, problem) ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected.intValue == index, enabled = idle && problem == null) {
                                selected.intValue = index
                            },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected.intValue == index, onClick = null, enabled = idle && problem == null)
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(suite.label)
                            Text(
                                if (problem == null) suite.id else "Not available here",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }

            when (current) {
                is Phase.Compare -> Section("Compare this code with the other phone") {
                    Text(
                        current.pending.sas,
                        fontSize = 40.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                    )
                    Text("${current.pending.suite.label} · session ${current.pending.sessionId}", style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { current.answer.complete(true) }) { Text("Codes match") }
                        OutlinedButton(onClick = { current.answer.complete(false) }) { Text("They differ") }
                    }
                }
                is Phase.Listening -> Section("Waiting for senders") {
                    Text("On the other phone, connect to this phone's Wi-Fi or hotspot address:")
                    if (current.addresses.isEmpty()) Text("(no network address; join Wi-Fi or turn on a hotspot)")
                    current.addresses.forEach { (ip, iface) ->
                        val address = if (current.port == TcpTransport.DEFAULT_PORT) ip else "$ip:${current.port}"
                        val hint = if (isLocalNetwork(iface)) iface else "$iface, probably not reachable"
                        Text("$address  ($hint)", fontFamily = FontFamily.Monospace)
                    }
                    Text("Keeps listening until you stop it.", style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = ::stop) { Text("Stop") }
                }
                is Phase.Receiving -> Section("Connected to ${current.peer}") {
                    Text("Code ${current.sas} · ${current.received} item(s) received. The sender can keep sending until it disconnects.")
                    OutlinedButton(onClick = ::stop) { Text("Stop receiving") }
                }
                is Phase.Connected -> Section("Connected to ${current.peer}") {
                    Text("Code ${current.sas} · ${current.suite}", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = message,
                        onValueChange = { message = it },
                        label = { Text("Message") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            val bytes = message.toByteArray()
                            send(Payload("message.txt", bytes.size.toLong()) { ByteArrayInputStream(bytes) })
                        }) { Text("Send message") }
                        OutlinedButton(onClick = { pickFile.launch(arrayOf("*/*")) }) { Text("Send file") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { send(randomPayload(1 shl 20)) }) { Text("1 MB test") }
                        OutlinedButton(onClick = { send(randomPayload(10 shl 20)) }) { Text("10 MB test") }
                    }
                    OutlinedButton(onClick = { current.outbox.close() }) { Text("Disconnect") }
                }
                is Phase.Busy -> Section(current.what) {
                    OutlinedButton(onClick = ::stop) { Text("Cancel") }
                }
                Phase.Idle -> {
                    Section("Test on this phone") {
                        Text("Runs every approach over loopback, including tampering, replay and man-in-the-middle attacks.")
                        Button(onClick = ::selfTest) { Text("Run self-test") }
                    }
                    Section("Receive") {
                        Text("Both phones on the same Wi-Fi or hotspot. Port ${TcpTransport.DEFAULT_PORT}.")
                        Button(onClick = ::receive) { Text("Wait for senders") }
                    }
                    Section("Send") {
                        OutlinedTextField(
                            value = target,
                            onValueChange = { target = it },
                            label = { Text("Other phone's address (e.g. 192.168.1.20)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            "Compare the code once; then send as many messages and files as you like.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(onClick = { connect(target) }) { Text("Connect") }
                    }
                }
            }

            Section("Log") {
                if (log.isEmpty()) Text("Nothing yet.", style = MaterialTheme.typography.bodySmall)
                log.forEach {
                    Text(
                        it.text,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (it.ok) Color.Unspecified else MaterialTheme.colorScheme.error,
                    )
                }
                if (log.isNotEmpty()) OutlinedButton(onClick = { log.clear() }) { Text("Clear") }
            }
        }
    }

    @Composable
    private fun Section(title: String, content: @Composable () -> Unit) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                content()
            }
        }
    }

    private companion object {
        const val MAX_RECEIVE_BYTES = 200L * 1024 * 1024
        const val PREVIEW_BYTES = 2048

        /** Wi-Fi, hotspot, Wi-Fi Direct and Ethernet interfaces: the ones another phone nearby can reach. */
        private val LOCAL_INTERFACES = listOf("wlan", "swlan", "ap", "p2p", "eth")

        /** Mobile-data interfaces (Qualcomm, MediaTek): never reachable from the other phone. */
        private val MOBILE_INTERFACES = listOf("rmnet", "ccmni", "v4-rmnet", "v4-ccmni")

        fun isLocalNetwork(iface: String) = LOCAL_INTERFACES.any { iface.startsWith(it) }

        /**
         * IPv4 addresses of this phone with their interface, Wi-Fi and hotspot first. Others (VPN tunnels, a
         * carrier's 100.x address) are listed last, marked as probably not reachable.
         */
        fun localAddresses(): List<Pair<String, String>> = runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .filter { nif -> nif.isUp && !nif.isLoopback && MOBILE_INTERFACES.none { nif.name.startsWith(it) } }
                .flatMap { nif ->
                    nif.inetAddresses.toList().filterIsInstance<Inet4Address>().map { it.hostAddress.orEmpty() to nif.name }
                }
                .filter { it.first.isNotEmpty() }
                .sortedBy { if (isLocalNetwork(it.second)) 0 else 1 }
        }.getOrDefault(emptyList())

        /** Keeps the sender's file name from escaping the received folder. */
        fun safeName(name: String): String =
            name.substringAfterLast('/').substringAfterLast('\\')
                .replace(Regex("[^A-Za-z0-9._ -]"), "_")
                .trimStart('.')
                .take(100)
                .ifBlank { "received.bin" }
    }
}
