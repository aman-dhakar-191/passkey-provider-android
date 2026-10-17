package io.github.amandhakar.passkey.recovery

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.github.amandhakar.passkey.R
import io.github.amandhakar.passkey.transfer.PasskeyBundle
import java.util.concurrent.TimeUnit

/**
 * Daily, offline: if the backup needs attention (a keeper's check is due or failed, the file is missing or out
 * of date), posts a notification, at most every [REMIND_EVERY_DAYS] days. So a lost piece is found while the
 * phone still works, not after it's gone.
 */
class BackupReminderWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val store = RecoveryStore.get(applicationContext)
        val set = store.set.value ?: return Result.success()
        val now = System.currentTimeMillis()
        if (now - set.lastReminderAt < TimeUnit.DAYS.toMillis(REMIND_EVERY_DAYS)) return Result.success()
        val movable = PasskeyBundle.movable(applicationContext).map { it.credentialId }.toSet()
        val report = BackupHealth.report(set, movable, now)
        if (report.level == BackupHealth.Level.OK) return Result.success()
        if (ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            return Result.success()
        }

        val manager = applicationContext.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "Backup checks", NotificationManager.IMPORTANCE_DEFAULT))
        val open = PendingIntent.getActivity(
            applicationContext,
            0,
            Intent(applicationContext, BackupActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val title = if (report.level == BackupHealth.Level.PROBLEM) "Your passkey backup can't restore right now" else "Time to check your passkey backup"
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL)
            .setSmallIcon(R.drawable.ic_key)
            .setContentTitle(title)
            .setContentText(report.messages.firstOrNull() ?: "Open Backup & recovery")
            .setStyle(NotificationCompat.BigTextStyle().bigText(report.messages.joinToString("\n")))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
        store.update { it?.copy(lastReminderAt = now) }
        return Result.success()
    }

    companion object {
        private const val CHANNEL = "backup"
        private const val NOTIFICATION_ID = 2
        private const val REMIND_EVERY_DAYS = 14L

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<BackupReminderWorker>(1, TimeUnit.DAYS).build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork("backup-check", ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
