package io.github.amandhakar.passkey

import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Process
import java.io.File
import kotlin.system.exitProcess

/**
 * Catches crashes and shows them in [CrashActivity], so a stack trace can be copied off the phone
 * without a computer. Installed in attachBaseContext so it also catches crashes in startup providers.
 */
class PasskeyApp : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        if (Application.getProcessName().endsWith(":crash")) return
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            try {
                val file = crashFile(base)
                // A crash right after the last one means the crash screen itself is failing: give up.
                if (System.currentTimeMillis() - file.lastModified() < 3_000) {
                    previous?.uncaughtException(thread, error)
                    return@setDefaultUncaughtExceptionHandler
                }
                file.writeText(
                    "App ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})\n" +
                        "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), " +
                        "${Build.MANUFACTURER} ${Build.MODEL}\n" +
                        "Thread: ${thread.name}\n\n" +
                        error.stackTraceToString(),
                )
                base.startActivity(
                    Intent(base, CrashActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
                )
            } catch (_: Throwable) {
                previous?.uncaughtException(thread, error)
                return@setDefaultUncaughtExceptionHandler
            }
            Process.killProcess(Process.myPid())
            exitProcess(10)
        }
    }

    companion object {
        fun crashFile(context: Context) = File(context.filesDir, "last_crash.txt")
    }
}
