package io.github.amandhakar.passkey.update

import android.content.Context
import java.io.File

/** GitHub channel: the app updates itself from GitHub Releases. The store channel has a stub instead. */
object Updater {
    const val ENABLED = true

    fun schedule(context: Context) = UpdateWorker.schedule(context)

    /** Blocking; call from a background thread. */
    fun latestRelease(): Release? = UpdateManager.latestRelease()

    fun isNewer(release: Release) = UpdateManager.isNewer(release)

    fun canInstall(context: Context) = UpdateManager.canInstall(context)

    /** Blocking download; [onProgress] gets 0..1. */
    fun download(context: Context, release: Release, onProgress: (Float) -> Unit): File =
        UpdateManager.download(context, release, onProgress)

    fun install(context: Context, apk: File) = UpdateManager.install(context, apk)
}
