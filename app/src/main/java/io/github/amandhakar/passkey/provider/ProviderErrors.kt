package io.github.amandhakar.passkey.provider

import android.content.Context
import android.os.Build
import android.util.Log
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
 * Each step of a request is noted too, so a report shows how far a request got. GitHub builds write every
 * step; store builds write a request's steps only if it goes wrong, and never log successful sign-ins.
 */
object ProviderErrors {
    private const val MAX_ENTRIES = 30
    private const val SEPARATOR = "\n----------\n"
    // Store builds keep only problems (see RequestLog); GitHub and test builds keep every step.
    private val requests = RequestLog(logEverything = BuildConfig.LOG_ALL_REQUESTS || BuildConfig.SELF_TEST)
    private val state = MutableStateFlow<String?>(null)
    val latest: StateFlow<String?> = state.asStateFlow()

    private fun file(context: Context) = File(context.applicationContext.filesDir, "provider_errors.txt")

    fun load(context: Context) {
        state.value = runCatching { file(context).readText() }.getOrNull()?.takeIf { it.isNotBlank() }
    }

    fun record(context: Context, operation: String, error: Throwable) {
        Toast.makeText(context, "$operation failed: ${error.message ?: error.javaClass.simpleName}", Toast.LENGTH_LONG)
            .show()
        append(
            context,
            requests.problem(
                "$operation FAILED\n" +
                    "App ${BuildConfig.VERSION_NAME}, Android ${Build.VERSION.RELEASE}, ${Build.MANUFACTURER} ${Build.MODEL}\n" +
                    error.stackTraceToString().lineSequence().take(40).joinToString("\n"),
            ),
        )
    }

    /** Notes a step of a passkey request (no toast). Store builds only write it if the request then fails. */
    fun note(context: Context, message: String) {
        requests.step(message)?.let { append(context, it) }
    }

    /** Notes a problem that isn't an exception (e.g. no passkey for the site), with the steps that led to it. */
    fun problem(context: Context, message: String) = append(context, requests.problem(message))

    /** Notes that a request succeeded. Store builds don't log successes. */
    fun succeeded(context: Context, message: String) {
        requests.succeeded(message)?.let { append(context, it) }
    }

    @Synchronized
    private fun append(context: Context, message: String) {
        // The emulator test reads the log from logcat when the build is not debuggable ("minified").
        if (BuildConfig.SELF_TEST) Log.i("PasskeyVault", message)
        val entry = "${DateFormat.getTimeInstance().format(Date())} $message"
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
