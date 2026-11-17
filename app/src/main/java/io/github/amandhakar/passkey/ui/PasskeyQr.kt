package io.github.amandhakar.passkey.ui

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning

/**
 * Scanning the QR code a computer shows to sign in with a passkey from this phone (cross-device sign-in).
 * The phone connects to the computer over Bluetooth and asks Credential Manager, which offers this app's
 * passkeys; the app only hands Google Play services the code. Used by the main screen's button, the "Scan QR"
 * launcher icon and the long-press shortcut. [done] runs once the scan is over, whatever its outcome.
 */
internal object PasskeyQr {
    private const val PLAY_SERVICES = "com.google.android.gms"

    fun scan(activity: Activity, done: () -> Unit = {}) {
        val app = activity.applicationContext
        fun toast(message: String) = Toast.makeText(app, message, Toast.LENGTH_LONG).show()
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(activity, options).startScan()
            .addOnSuccessListener { barcode ->
                val raw = barcode.rawValue.orEmpty()
                if (!raw.startsWith("FIDO:/", ignoreCase = true)) {
                    toast("That is not a passkey QR code")
                    return@addOnSuccessListener
                }
                val uri = Uri.parse(raw)
                // The code holds the secret for the desktop sign-in, so it goes only to Google Play services
                // (which runs that sign-in), never to another app that also claims FIDO links.
                val launched = listOf(uri, uri.normalizeScheme()).any {
                    try {
                        activity.startActivity(Intent(Intent.ACTION_VIEW, it).setPackage(PLAY_SERVICES))
                        true
                    } catch (_: ActivityNotFoundException) {
                        false
                    }
                }
                if (!launched) toast("Google Play services is needed for cross-device sign-in")
            }
            .addOnFailureListener { toast("Scanner unavailable: ${it.message}") }
            .addOnCompleteListener { done() }
    }
}
