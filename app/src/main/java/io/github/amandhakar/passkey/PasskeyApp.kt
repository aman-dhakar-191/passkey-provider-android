package io.github.amandhakar.passkey

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.os.Process
import java.io.File
import kotlin.system.exitProcess

/**
 * In store builds, hides every screen from screenshots, screen recording and the Recents preview, since
 * they show which sites the user has passkeys for. GitHub builds allow screenshots (for bug reports).
 *
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

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.BLOCK_SCREENSHOTS) registerActivityLifecycleCallbacks(BlockScreenshots)
    }

    private object BlockScreenshots : ActivityLifecycleCallbacks {
        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }

        override fun onActivityStarted(activity: Activity) = Unit
        override fun onActivityResumed(activity: Activity) = Unit
        override fun onActivityPaused(activity: Activity) = Unit
        override fun onActivityStopped(activity: Activity) = Unit
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
        override fun onActivityDestroyed(activity: Activity) = Unit
    }

    companion object {
        fun crashFile(context: Context) = File(context.filesDir, "last_crash.txt")
    }
}
