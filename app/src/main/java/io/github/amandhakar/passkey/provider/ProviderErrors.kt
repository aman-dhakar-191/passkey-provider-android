package io.github.amandhakar.passkey.provider

import android.content.Context
import android.os.Build
import android.widget.Toast
import io.github.amandhakar.passkey.BuildConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.text.DateFormat
import java.util.Date

/**
 * Browsers and Windows replace a provider's error with a generic "something went wrong", so failed
 * passkey operations are also shown as a toast and kept here, where the main screen can show them.
 */
object ProviderErrors {
    private const val MAX_ENTRIES = 10
    private const val SEPARATOR = "\n----------\n"
    private val state = MutableStateFlow<String?>(null)
    val latest: StateFlow<String?> = state.asStateFlow()

    private fun file(context: Context) = File(context.applicationContext.filesDir, "provider_errors.txt")

    fun load(context: Context) {
        state.value = runCatching { file(context).readText() }.getOrNull()?.takeIf { it.isNotBlank() }
    }

    @Synchronized
    fun record(context: Context, operation: String, error: Throwable) {
        Toast.makeText(context, "$operation failed: ${error.message ?: error.javaClass.simpleName}", Toast.LENGTH_LONG)
            .show()
        val entry = "${DateFormat.getDateTimeInstance().format(Date())} - $operation failed\n" +
            "App ${BuildConfig.VERSION_NAME}, Android ${Build.VERSION.RELEASE}, ${Build.MANUFACTURER} ${Build.MODEL}\n" +
            error.stackTraceToString().lineSequence().take(40).joinToString("\n")
        val previous = runCatching { file(context).readText() }.getOrDefault("")
            .split(SEPARATOR).filter { it.isNotBlank() }
        val text = (listOf(entry) + previous).take(MAX_ENTRIES).joinToString(SEPARATOR)
        runCatching { file(context).writeText(text) }
        state.value = text
    }

    fun clear(context: Context) {
        file(context).delete()
        state.value = null
    }
}
