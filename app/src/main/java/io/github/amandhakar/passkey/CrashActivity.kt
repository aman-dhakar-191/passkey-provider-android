package io.github.amandhakar.passkey

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.widget.Button
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/** Plain-framework screen (no Compose/AndroidX) so it works even when the rest of the app is broken. */
class CrashActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val report = runCatching { PasskeyApp.crashFile(this).readText() }.getOrDefault("No crash report found.")
        val pad = (16 * resources.displayMetrics.density).toInt()

        val title = TextView(this).apply {
            text = "The app crashed. Copy or share this report so it can be fixed."
            textSize = 16f
            setPadding(0, 0, 0, pad)
        }
        val copy = Button(this).apply {
            text = "Copy"
            setOnClickListener {
                getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("Crash report", report))
                Toast.makeText(this@CrashActivity, "Copied", Toast.LENGTH_SHORT).show()
            }
        }
        val share = Button(this).apply {
            text = "Share"
            setOnClickListener {
                val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, report)
                startActivity(Intent.createChooser(send, "Share crash report"))
            }
        }
        val buttons = LinearLayout(this).apply {
            addView(copy)
            addView(share)
        }
        val trace = TextView(this).apply {
            text = report
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(0, pad, 0, pad)
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 3, pad, pad)
            addView(title)
            addView(buttons)
            addView(HorizontalScrollView(this@CrashActivity).apply { addView(trace) })
        }
        setContentView(ScrollView(this).apply { addView(column) })
    }
}
