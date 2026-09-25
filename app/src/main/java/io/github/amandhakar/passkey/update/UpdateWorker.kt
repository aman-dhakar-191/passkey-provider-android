package io.github.amandhakar.passkey.update

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.github.amandhakar.passkey.R
import io.github.amandhakar.passkey.ui.MainActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/** Daily background check that posts a notification when a newer release exists. */
class UpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    // Lint flags notify() in the store build, which does not declare POST_NOTIFICATIONS. That build never
    // schedules this worker (SELF_UPDATE=false), and the permission is checked at runtime below anyway.
    @SuppressLint("NotificationPermission")
    override suspend fun doWork(): Result {
        val release = withContext(Dispatchers.IO) { runCatching { UpdateManager.latestRelease() }.getOrNull() }
            ?: return Result.success()
        if (!UpdateManager.isNewer(release)) return Result.success()

        val prefs = applicationContext.getSharedPreferences("updates", Context.MODE_PRIVATE)
        if (prefs.getString("notified", null) == release.version) return Result.success()
        if (ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            return Result.success()
        }

        val manager = applicationContext.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "App updates", NotificationManager.IMPORTANCE_DEFAULT),
        )
        val open = PendingIntent.getActivity(
            applicationContext,
            0,
            Intent(applicationContext, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL)
            .setSmallIcon(R.drawable.ic_key)
            .setContentTitle("Update available")
            .setContentText("Version ${release.version} is ready to install")
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        manager.notify(1, notification)
        prefs.edit().putString("notified", release.version).apply()
        return Result.success()
    }

    companion object {
        private const val CHANNEL = "updates"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<UpdateWorker>(1, TimeUnit.DAYS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork("update-check", ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
