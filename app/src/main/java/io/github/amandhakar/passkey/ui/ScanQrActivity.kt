package io.github.amandhakar.passkey.ui

import android.os.Bundle
import androidx.activity.ComponentActivity

/**
 * The "Scan QR" launcher icon (and the app icon's long-press shortcut): opens the passkey QR scanner straight
 * away, with no screen of its own, and closes when the scan is over. It runs in its own task, so it scans even
 * when the main app is already open in the background.
 */
class ScanQrActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) PasskeyQr.scan(this) { finish() } else finish()
    }
}
