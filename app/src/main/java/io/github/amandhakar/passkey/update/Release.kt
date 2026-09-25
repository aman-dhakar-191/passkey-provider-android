package io.github.amandhakar.passkey.update

/** A published app release (shared by both channels so the UI can show update state). */
data class Release(
    val version: String,
    val apkUrl: String,
    val apkSize: Long,
    val sha256: String?,
    val notes: String,
    val pageUrl: String,
)
