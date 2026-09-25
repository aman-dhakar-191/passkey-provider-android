package io.github.amandhakar.passkey.update

import android.content.Context
import java.io.File

/**
 * Store channel (Google Play, Indus Appstore): the store delivers updates, so this build contains no
 * update code at all, only this stub. CI checks the built store app for update code and permissions.
 */
object Updater {
    const val ENABLED = false

    fun schedule(context: Context) = Unit

    fun latestRelease(): Release? = null

    fun isNewer(release: Release) = false

    fun canInstall(context: Context) = false

    fun download(context: Context, release: Release, onProgress: (Float) -> Unit): File =
        throw UnsupportedOperationException("Updates come from the store")

    fun install(context: Context, apk: File): Unit = throw UnsupportedOperationException("Updates come from the store")
}
