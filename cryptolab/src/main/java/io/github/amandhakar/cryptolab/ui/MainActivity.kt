package io.github.amandhakar.cryptolab.ui

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import io.github.amandhakar.cryptolab.android.BluetoothTransport
import io.github.amandhakar.cryptolab.android.LabSuites
import io.github.amandhakar.cryptolab.android.QrCode
import io.github.amandhakar.cryptolab.core.CipherSuite
import io.github.amandhakar.cryptolab.core.Connection
import io.github.amandhakar.cryptolab.core.Handshake
import io.github.amandhakar.cryptolab.core.Invite
import io.github.amandhakar.cryptolab.core.Listener
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
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.net.Inet4Address
import java.net.NetworkInterface
import java.security.SecureRandom
import java.text.DateFormat
import java.util.Date
import kotlin.coroutines.cancellation.CancellationException

class MainActivity : ComponentActivity() {
    private class LogLine(val ok: Boolean, val text: String)

    /** How the two phones reach each other. The secure channel on top is the same for both. */
    private enum class Medium(val label: String) {
        WIFI("Wi-Fi or hotspot (TCP)"),
        BLUETOOTH("Bluetooth (RFCOMM)"),
    }

    /** What the screen is doing; only one session at a time. */
    private sealed interface Phase {
        data object Idle : Phase
        data class Busy(val what: String) : Phase

        /** Receiver: waiting for senders. [qr] holds this phone's address and the session's secret. */
        class Listening(val medium: Medium, val lines: List<String>, val qr: Bitmap) : Phase
        class Compare(val pending: PendingChannel, val answer: CompletableDeferred<Boolean>) : Phase

        /** Receiver: a sender is connected; everything it sends is received until it disconnects. */
        data class Receiving(val peer: String, val auth: String, val received: Int) : Phase

        /** Sender: the channel is authenticated; send as many items as you like over it. */
        class Connected(val peer: String, val auth: String, val suite: String, val outbox: Channel<Payload>) : Phase
    }

    /** Something to send: a name, its size and a way to read it. */
    private class Payload(val name: String, val size: Long, val open: () -> InputStream)

    private val log = mutableStateListOf<LogLine>()
    private val suites = mutableStateListOf<Pair<CipherSuite, String?>>()
    private val selected = mutableIntStateOf(0)
    private val medium = mutableStateOf(Medium.WIFI)
    private val phase = mutableStateOf<Phase>(Phase.Idle)
    private val bluetoothDevices = mutableStateListOf<BluetoothDevice>()
    private val bluetoothScanning = mutableStateOf(false)
    private var job: Job? = null
    private var server: Closeable? = null
    private var openResource: Closeable? = null
    private val random = SecureRandom()

    /** A Bluetooth name the QR code asked for, completed when discovery finds that phone. */
    private var wantedDevice: Pair<String, CompletableDeferred<BluetoothDevice>>? = null

    private var afterPermission: (() -> Unit)? = null
    private val permissionLauncher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
        val action = afterPermission
        afterPermission = null
        if (granted.values.all { it }) action?.invoke() else note(false, "Bluetooth permission was not granted")
    }
    private val discoverableLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_CANCELED) {
            note(false, "Not discoverable: only phones paired with this one can find it")
        } else {
            note(true, "Discoverable to nearby phones for ${result.resultCode} s")
        }
    }

    private val discoveryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java) ?: return
                    if (bluetoothDevices.none { it == device }) bluetoothDevices.add(device)
                    val wanted = wantedDevice
                    if (wanted != null && BluetoothTransport.deviceName(device) == wanted.first) wanted.second.complete(device)
                }
                BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> bluetoothScanning.value = false
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        ContextCompat.registerReceiver(
            this,
            discoveryReceiver,
            IntentFilter().apply {
                addAction(BluetoothDevice.ACTION_FOUND)
                addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
            },
            ContextCompat.RECEIVER_EXPORTED, // sent by the system's Bluetooth stack
        )
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
        unregisterReceiver(discoveryReceiver)
        if (BluetoothTransport.hasPermissions(this)) {
            BluetoothTransport.adapter(this)?.let { runCatching { BluetoothTransport.cancelDiscovery(it) } }
        }
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

    /** Runs [action] once Bluetooth permissions are granted and Bluetooth is on. */
    private fun withBluetooth(action: (BluetoothAdapter) -> Unit) {
        if (!BluetoothTransport.hasPermissions(this)) {
            afterPermission = { withBluetooth(action) }
            permissionLauncher.launch(BluetoothTransport.permissions)
            return
        }
        val adapter = BluetoothTransport.adapter(this) ?: return note(false, "This phone has no Bluetooth")
        if (!BluetoothTransport.isOn(adapter)) return note(false, "Turn on Bluetooth first")
        action(adapter)
    }

    private fun findPhones() = withBluetooth { adapter ->
        bluetoothDevices.clear()
        bluetoothDevices.addAll(BluetoothTransport.pairedDevices(adapter))
        BluetoothTransport.startDiscovery(adapter)
        bluetoothScanning.value = true
    }

    private fun stop() {
        runCatching { server?.close() }
        server = null
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
                runCatching { server?.close() }
                server = null
                runCatching { openResource?.close() }
                openResource = null
                wantedDevice = null
                phase.value = Phase.Idle
            }
        }
    }

    /**
     * Finishes authentication: with the QR secret the keys are simply confirmed; otherwise this person
     * compares the code with the other phone's.
     */
    private suspend fun authenticate(pending: PendingChannel): SecureChannel {
        openResource = pending
        val match = if (pending.usesQrSecret) {
            note(true, "Key exchange done with ${pending.suite.label}, authenticated by the QR code's secret")
            phase.value = Phase.Busy("Confirming keys…")
            true
        } else {
            note(true, "Key exchange done with ${pending.suite.label}, code ${pending.sas}, session ${pending.sessionId}")
            val answer = CompletableDeferred<Boolean>()
            phase.value = Phase.Compare(pending, answer)
            answer.await().also {
                phase.value = Phase.Busy(if (it) "Waiting for the other phone to confirm…" else "Closing…")
            }
        }
        val channel = withContext(Dispatchers.IO) { pending.confirm(match) }
        openResource = channel
        note(true, if (pending.usesQrSecret) "Keys confirmed; channel open" else "Both people confirmed the code; channel open")
        return channel
    }

    private fun authLabel(pending: PendingChannel) = if (pending.usesQrSecret) "QR code" else "code ${pending.sas}"

    private fun startReceiving() {
        if (medium.value == Medium.BLUETOOTH) {
            withBluetooth { adapter ->
                // Unpaired phones can only find this one while it's discoverable.
                runCatching { discoverableLauncher.launch(BluetoothTransport.discoverableIntent(300)) }
                receive { bluetoothListening(adapter) }
            }
        } else {
            receive { tcpListening() }
        }
    }

    /** An open listener and how to reach it: the lines to show and the QR code's contents for a secret. */
    private class Opened(val listener: Listener, val lines: List<String>, val invite: (ByteArray) -> Invite)

    private suspend fun tcpListening(): Opened {
        val listener = withContext(Dispatchers.IO) { TcpTransport.TcpListener() }
        val port = listener.port
        val addresses = localAddresses()
        val lines = addresses.map { (ip, iface) ->
            val address = if (port == TcpTransport.DEFAULT_PORT) ip else "$ip:$port"
            "$address  (${if (isLocalNetwork(iface)) iface else "$iface, probably not reachable"})"
        }.ifEmpty { listOf("(no network address; join Wi-Fi or turn on a hotspot)") }
        val targets = addresses.filter { isLocalNetwork(it.second) }.ifEmpty { addresses }.map { "${it.first}:$port" }
            .ifEmpty { listOf("127.0.0.1:$port") }
        return Opened(listener, lines) { Invite(Invite.TCP, targets, it) }
    }

    private suspend fun bluetoothListening(adapter: BluetoothAdapter): Opened {
        val listener = withContext(Dispatchers.IO) { BluetoothTransport.BluetoothListener(adapter) }
        val name = BluetoothTransport.name(adapter).ifBlank { "Unnamed phone" }
        return Opened(listener, listOf("Bluetooth name: $name")) { Invite(Invite.BLUETOOTH, listOf(name), it) }
    }

    /** Listens until Stop. Each sender scans the QR code (or compares codes), then sends any number of items. */
    private fun receive(open: suspend () -> Opened) = session {
        val opened = open()
        server = opened.listener
        // A fresh secret for this listening session; anyone who sees the QR code can connect while it's shown.
        val secret = ByteArray(Handshake.QR_SECRET_SIZE).also { random.nextBytes(it) }
        val qr = withContext(Dispatchers.Default) { QrCode.bitmap(opened.invite(secret).encode()) }
        val dir = File(cacheDir, "received").apply { mkdirs() }
        while (true) {
            phase.value = Phase.Listening(medium.value, opened.lines, qr)
            val connection = withContext(Dispatchers.IO) { opened.listener.accept() }
            openResource = connection
            val peer = connection.peer
            try {
                note(true, "Connection from $peer")
                phase.value = Phase.Busy("Key exchange with $peer…")
                val pending = withContext(Dispatchers.IO) { Handshake.respond(connection, ::suiteFor, secret) }
                val channel = authenticate(pending)
                phase.value = Phase.Receiving(peer, authLabel(pending), 0)
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
                // One failed sender (wrong code, old QR code, dropped connection, ...) doesn't stop the receiver.
                note(false, "$peer: ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                runCatching { connection.close() }
                openResource = null
            }
        }
    }

    /**
     * Connects with [open], authenticates (QR secret, or comparing codes when [qrSecret] is null), then sends
     * whatever is queued until Disconnect.
     */
    private fun sendSession(target: String, qrSecret: ByteArray?, open: suspend () -> Connection) = session {
        val suite = selectedSuite ?: throw IllegalStateException("Choose a suite that works on this phone")
        phase.value = Phase.Busy("Connecting to $target…")
        val connection = open()
        openResource = connection
        phase.value = Phase.Busy("Key exchange…")
        val pending = withContext(Dispatchers.IO) { Handshake.initiate(connection, suite, qrSecret) }
        val channel = authenticate(pending)
        val outbox = Channel<Payload>(Channel.UNLIMITED)
        val connected = Phase.Connected(connection.peer, authLabel(pending), suite.label, outbox)
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

    private fun connectWifi(target: String) {
        // Pasted or typed addresses sometimes carry spaces ("100. 86.77.63").
        val address = target.filterNot { it.isWhitespace() }
        val host = address.substringBefore(':')
        val port = address.substringAfter(':', "").toIntOrNull() ?: TcpTransport.DEFAULT_PORT
        if (host.isEmpty()) return note(false, "Enter the other phone's address")
        sendSession("$host:$port", null) { withContext(Dispatchers.IO) { TcpTransport.connect(host, port) } }
    }

    private fun connectBluetooth(device: BluetoothDevice) = withBluetooth { adapter ->
        sendSession(BluetoothTransport.label(device), null) {
            withContext(Dispatchers.IO) { BluetoothTransport.connect(adapter, device) }
        }
    }

    private fun scanQr() {
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(this, options).startScan()
            .addOnSuccessListener { barcode ->
                runCatching { Invite.parse(barcode.rawValue.orEmpty()) }
                    .onSuccess(::join)
                    .onFailure { note(false, it.message ?: "Not a Crypto Lab QR code") }
            }
            .addOnFailureListener { note(false, "QR scanner: ${it.message}") }
    }

    /** Connects to the phone whose QR code was scanned, using its secret instead of comparing codes. */
    private fun join(invite: Invite) {
        when (invite.transport) {
            Invite.TCP -> sendSession(invite.targets.first(), invite.secret) { firstReachable(invite.targets) }
            Invite.BLUETOOTH -> withBluetooth { adapter ->
                val name = invite.targets.first()
                sendSession(name, invite.secret) {
                    val device = findBluetoothDevice(adapter, name)
                    withContext(Dispatchers.IO) { BluetoothTransport.connect(adapter, device) }
                }
            }
        }
    }

    /** The QR code lists every Wi-Fi/hotspot address of the receiver; use the first that answers. */
    private suspend fun firstReachable(targets: List<String>): Connection = withContext(Dispatchers.IO) {
        val failures = mutableListOf<String>()
        for (target in targets) {
            val host = target.substringBefore(':')
            val port = target.substringAfter(':', "").toIntOrNull() ?: TcpTransport.DEFAULT_PORT
            try {
                return@withContext TcpTransport.connect(host, port, timeoutMs = 4_000)
            } catch (e: IOException) {
                failures += "$target (${e.javaClass.simpleName})"
            }
        }
        throw IOException("None of the QR code's addresses answered: ${failures.joinToString()}. Are both phones on the same Wi-Fi?")
    }

    /** A paired phone with that Bluetooth name, or one found by scanning (the receiver is discoverable). */
    private suspend fun findBluetoothDevice(adapter: BluetoothAdapter, name: String): BluetoothDevice {
        BluetoothTransport.pairedDevices(adapter).firstOrNull { BluetoothTransport.deviceName(it) == name }?.let { return it }
        phase.value = Phase.Busy("Looking for \"$name\" over Bluetooth…")
        val found = CompletableDeferred<BluetoothDevice>()
        wantedDevice = name to found
        try {
            BluetoothTransport.startDiscovery(adapter)
            bluetoothScanning.value = true
            return withTimeoutOrNull(DISCOVERY_TIMEOUT_MS) { found.await() }
                ?: throw IOException("\"$name\" wasn't found nearby. Is it waiting for senders, with Bluetooth on?")
        } finally {
            wantedDevice = null
        }
    }

    private fun selfTest() = session {
        phase.value = Phase.Busy("Self-test running…")
        val working = suites.filter { it.second == null }.map { it.first }
        withContext(Dispatchers.Default) {
            SelfTest.run(working) { note(it.ok, it.text) }
        }
        note(true, "Self-test finished")
    }

    /** Queues [payload] on the connected session, if there is one. */
    private fun send(payload: Payload) {
        (phase.value as? Phase.Connected)?.outbox?.trySend(payload)
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
        val data = ByteArray(bytes).also { random.nextBytes(it) }
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
                    "encryption, authenticated by a QR code or by comparing a 6-digit code.",
                style = MaterialTheme.typography.bodyMedium,
            )

            Section("Encryption (the sender's choice is used)") {
                suites.forEachIndexed { index, (suite, problem) ->
                    Choice(
                        selected = selected.intValue == index,
                        enabled = idle && problem == null,
                        title = suite.label,
                        subtitle = if (problem == null) suite.id else "Not available here",
                    ) { selected.intValue = index }
                }
            }

            Section("Transport") {
                Medium.entries.forEach { m ->
                    Choice(selected = medium.value == m, enabled = idle, title = m.label, subtitle = null) { medium.value = m }
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
                is Phase.Listening -> Section("Waiting for senders (${current.medium.label})") {
                    Text("On the other phone: Send → Scan QR code.")
                    Image(
                        bitmap = current.qr.asImageBitmap(),
                        contentDescription = "QR code with this phone's address and a one-time secret",
                        modifier = Modifier.size(240.dp),
                    )
                    current.lines.forEach { Text(it, fontFamily = FontFamily.Monospace) }
                    Text(
                        "Or connect manually and compare codes. Keeps listening until you stop it.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = ::stop) { Text("Stop") }
                }
                is Phase.Receiving -> Section("Connected to ${current.peer}") {
                    Text("Authenticated by ${current.auth} · ${current.received} item(s) received. The sender can keep sending until it disconnects.")
                    OutlinedButton(onClick = ::stop) { Text("Stop receiving") }
                }
                is Phase.Connected -> Section("Connected to ${current.peer}") {
                    Text("Authenticated by ${current.auth} · ${current.suite}", style = MaterialTheme.typography.bodySmall)
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
                        Text("Runs every approach over loopback, including tampering, replay, man-in-the-middle and wrong-QR attacks.")
                        Button(onClick = ::selfTest) { Text("Run self-test") }
                    }
                    Section("Receive") {
                        Text(
                            if (medium.value == Medium.WIFI) {
                                "Both phones on the same Wi-Fi or hotspot. Shows a QR code for the sender to scan."
                            } else {
                                "Shows a QR code for the sender to scan, and makes this phone discoverable for 5 minutes."
                            },
                        )
                        Button(onClick = ::startReceiving) { Text("Wait for senders") }
                    }
                    Section("Send") {
                        Button(onClick = ::scanQr) { Text("Scan QR code") }
                        Text("Or connect manually and compare the 6-digit code:", style = MaterialTheme.typography.bodySmall)
                        if (medium.value == Medium.WIFI) {
                            OutlinedTextField(
                                value = target,
                                onValueChange = { target = it },
                                label = { Text("Other phone's address (e.g. 192.168.1.20)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedButton(onClick = { connectWifi(target) }) { Text("Connect") }
                        } else {
                            OutlinedButton(onClick = ::findPhones, enabled = !bluetoothScanning.value) {
                                Text(if (bluetoothScanning.value) "Scanning…" else "Find phones")
                            }
                            bluetoothDevices.forEach { device ->
                                Text(
                                    BluetoothTransport.label(device),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { connectBluetooth(device) }
                                        .padding(vertical = 8.dp),
                                )
                            }
                            if (bluetoothDevices.isNotEmpty()) {
                                Text("Tap the phone that is waiting for senders.", style = MaterialTheme.typography.bodySmall)
                            }
                        }
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
    private fun Choice(selected: Boolean, enabled: Boolean, title: String, subtitle: String?, onSelect: () -> Unit) {
        Row(
            Modifier
                .fillMaxWidth()
                .selectable(selected = selected, enabled = enabled, onClick = onSelect),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = null, enabled = enabled)
            Column(Modifier.padding(start = 8.dp)) {
                Text(title)
                if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall)
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
        const val DISCOVERY_TIMEOUT_MS = 20_000L

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
