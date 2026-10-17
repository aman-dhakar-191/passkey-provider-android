package io.github.amandhakar.passkey.recovery

import android.graphics.Bitmap
import androidx.fragment.app.FragmentActivity
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import io.github.amandhakar.passkey.transfer.QrCode
import io.github.amandhakar.securechannel.Connection
import io.github.amandhakar.securechannel.Handshake
import io.github.amandhakar.securechannel.Invite
import io.github.amandhakar.securechannel.LocalNetwork
import io.github.amandhakar.securechannel.QrReceiver
import io.github.amandhakar.securechannel.Suites
import io.github.amandhakar.securechannel.TcpTransport
import io.github.amandhakar.securechannel.Transfer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.security.SecureRandom
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Handing a key piece from one phone to another in person, over the same secure channel as moving passkeys:
 * the receiving phone shows a QR code with its Wi-Fi address and a one-time secret, the other phone scans it
 * and sends one small item. Only a phone that saw the QR code can connect. Used to give a piece to a keeper
 * and, when restoring, to get it back.
 */
internal object QrLink {
    /** Hand a piece to a keeper (the keeper shows the code). */
    const val KEEP = "passkeyvault-keep:v1"

    /** Give a piece back to a phone that is restoring (that phone shows the code). */
    const val RETURN = "passkeyvault-return:v1"

    private const val MAX_BYTES = 16L * 1024

    /**
     * Shows a QR code through [show] and returns the one item that the first phone with its secret sends.
     * [track] gets everything to close if the person cancels.
     */
    suspend fun receiveOne(
        prefix: String,
        track: (Closeable) -> Unit,
        show: (Bitmap, List<String>) -> Unit,
        ignored: (String) -> Unit,
    ): ByteArray {
        val listener = withContext(Dispatchers.IO) { TcpTransport.TcpListener(port = 0) }.also(track)
        val targets = LocalNetwork.inviteTargets(listener.port)
        if (targets.isEmpty()) throw IOException("No Wi-Fi address. Connect both phones to the same Wi-Fi or hotspot.")
        val secret = ByteArray(Handshake.QR_SECRET_SIZE).also { SecureRandom().nextBytes(it) }
        val qr = withContext(Dispatchers.Default) { QrCode.bitmap(Invite(Invite.TCP, targets, secret).encode(prefix)) }
        show(qr, targets)
        val channel = withContext(Dispatchers.IO) {
            QrReceiver.accept(listener, { id -> Suites.software.firstOrNull { it.id == id } }, secret) { peer, reason ->
                ignored("Ignored a connection from $peer (${reason.message ?: reason.javaClass.simpleName})")
            }
        }.also(track)
        secret.fill(0)
        listener.close()
        val received = ByteArrayOutputStream()
        withContext(Dispatchers.IO) { Transfer.receiveAll(channel, MAX_BYTES, { _, _ -> received }, maxItems = 1) {} }
        channel.close()
        return received.toByteArray()
    }

    /** Scans the other phone's QR code (made with [prefix]) and sends it [data]. */
    suspend fun sendOne(activity: FragmentActivity, prefix: String, data: ByteArray, track: (Closeable) -> Unit) {
        val invite = Invite.parse(scan(activity), prefix)
        require(invite.transport == Invite.TCP) { "Unsupported QR code" }
        withContext(Dispatchers.IO) {
            val connection = firstReachable(invite.targets).also(track)
            val pending = Handshake.initiate(connection, Suites.software.first(), invite.secret)
            val channel = pending.confirm(true).also(track)
            Transfer.send(channel, "piece", data.size.toLong(), data.inputStream())
            Transfer.finish(channel)
            channel.close()
        }
    }

    /** Google's code scanner: the app needs no camera permission. */
    suspend fun scan(activity: FragmentActivity): String = suspendCancellableCoroutine { cont ->
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(activity, options).startScan()
            .addOnSuccessListener { if (cont.isActive) cont.resume(it.rawValue.orEmpty()) }
            .addOnCanceledListener { if (cont.isActive) cont.resumeWithException(IllegalStateException("Cancelled")) }
            .addOnFailureListener { if (cont.isActive) cont.resumeWithException(IllegalStateException("QR scanner: ${it.message}")) }
    }

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
        throw IOException("Couldn't reach the other phone (${failures.joinToString()}). Are both phones on the same Wi-Fi?")
    }
}
