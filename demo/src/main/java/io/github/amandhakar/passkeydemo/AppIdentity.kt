package io.github.amandhakar.passkeydemo

import android.content.Context
import android.content.pm.PackageManager

/** Who this app is, as a passkey provider and a website see it. */
object AppIdentity {
    private fun certificate(context: Context): ByteArray {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
        ).signingInfo ?: error("This app has no signing information")
        val certs = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
        val cert = if (info.hasMultipleSigners()) certs.firstOrNull() else certs.lastOrNull()
        return cert?.toByteArray() ?: error("This app has no signing certificate")
    }

    /** The form assetlinks.json uses: uppercase hex pairs separated by colons. */
    fun fingerprint(context: Context): String =
        PasskeyVerifier.sha256(certificate(context)).joinToString(":") { "%02X".format(it) }

    /** What a passkey provider puts in clientDataJSON for a native app's request. */
    fun origin(context: Context): String =
        "android:apk-key-hash:" + PasskeyVerifier.b64u(PasskeyVerifier.sha256(certificate(context)))
}
