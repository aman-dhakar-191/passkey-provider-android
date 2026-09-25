package io.github.amandhakar.passkey.ui

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.PasskeyProviderService
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.provider.verifyUser
import io.github.amandhakar.passkey.update.Release
import io.github.amandhakar.passkey.update.Updater
import io.github.amandhakar.passkey.webauthn.Base64Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {
    // Self-update only in the github channel's release builds (debug builds have another package name).
    private val updatesEnabled = Updater.ENABLED && !BuildConfig.DEBUG
    private val providerEnabled = mutableStateOf(false)
    private val updateState = mutableStateOf<UpdateState>(UpdateState.Idle)
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (updatesEnabled) {
            Updater.schedule(this)
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            if (savedInstanceState == null) checkForUpdate(quiet = true)
        }
        // Used by the emulator test in CI (scripts/emulator_selftest.py); debug builds only.
        if (BuildConfig.DEBUG && savedInstanceState == null && intent.getBooleanExtra(EXTRA_RUN_SELF_TEST, false)) {
            lifecycleScope.launch { toast(SelfTest.run(this@MainActivity)) }
        }
        val store = PasskeyStore.get(this)
        setContent {
            PasskeyTheme {
                MainScreen(
                    passkeysFlow = store.passkeys,
                    problemsFlow = ProviderErrors.latest,
                    providerEnabled = providerEnabled.value,
                    updateState = updateState.value,
                    updatesEnabled = this.updatesEnabled,
                    versionName = BuildConfig.VERSION_NAME,
                    onOpenProviderSettings = ::openProviderSettings,
                    onScanQr = ::scanQr,
                    onSelfTest = { lifecycleScope.launch { toast(SelfTest.run(this@MainActivity)) } },
                    onDelete = ::deletePasskey,
                    onRename = { passkey, name -> store.rename(passkey.credentialId, name) },
                    onCheckUpdate = { checkForUpdate(quiet = false) },
                    onInstallUpdate = ::installUpdate,
                    onCopyProblems = ::copyProblems,
                    onClearProblems = { ProviderErrors.clear(this) },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        providerEnabled.value = isProviderEnabled()
        ProviderErrors.load(this)
    }

    private fun copyProblems() {
        val text = ProviderErrors.latest.value ?: return
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Passkey problems", text))
        toast("Copied")
    }

    private fun isProviderEnabled(): Boolean = runCatching {
        getSystemService(android.credentials.CredentialManager::class.java)
            .isEnabledCredentialProviderService(ComponentName(this, PasskeyProviderService::class.java))
    }.getOrDefault(false)

    private fun openProviderSettings() {
        // The first opens "Passwords, passkeys & accounts" (preferred service + on/off switches) on
        // Android 14+. Some phone makers only handle the variant with our package, or none of them.
        val intents = listOf(
            Intent("android.settings.CREDENTIAL_PROVIDER"),
            Intent("android.settings.CREDENTIAL_PROVIDER").setData(Uri.parse("package:$packageName")),
            Intent(Settings.ACTION_SETTINGS),
        )
        for (intent in intents) {
            try {
                startActivity(intent)
                return
            } catch (_: ActivityNotFoundException) {
            }
        }
    }

    /**
     * Desktop sign-in: the desktop browser shows a "FIDO:/..." QR code. Google Play services owns the
     * hybrid (caBLE) transport - Bluetooth proximity check plus the encrypted tunnel - and, once
     * connected, asks Credential Manager, which offers this app's passkeys. We just hand it the code.
     */
    private fun scanQr() {
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(this, options).startScan()
            .addOnSuccessListener { barcode ->
                val raw = barcode.rawValue.orEmpty()
                if (!raw.startsWith("FIDO:/", ignoreCase = true)) {
                    toast("That is not a passkey QR code")
                    return@addOnSuccessListener
                }
                val uri = Uri.parse(raw)
                val launched = listOf(uri, uri.normalizeScheme()).any {
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, it))
                        true
                    } catch (_: ActivityNotFoundException) {
                        false
                    }
                }
                if (!launched) toast("Google Play services is needed for cross-device sign-in")
            }
            .addOnFailureListener { toast("Scanner unavailable: ${it.message}") }
    }

    private fun deletePasskey(passkey: Passkey) {
        lifecycleScope.launch {
            val ok = runCatching { verifyUser("Delete passkey", "${passkey.userName} on ${passkey.rpId}") }
                .getOrElse { toast(it.message ?: "Cannot verify"); false }
            if (!ok) return@launch
            withContext(Dispatchers.IO) {
                PasskeyKeys.delete(Base64Url.decode(passkey.credentialId))
                PasskeyStore.get(this@MainActivity).remove(passkey.credentialId)
            }
            toast("Passkey deleted. Also remove it from your account settings on ${passkey.rpId}.")
        }
    }

    private fun checkForUpdate(quiet: Boolean) {
        updateState.value = UpdateState.Checking
        lifecycleScope.launch {
            updateState.value = try {
                val release = withContext(Dispatchers.IO) { Updater.latestRelease() }
                if (release != null && Updater.isNewer(release)) UpdateState.Available(release)
                else if (quiet) UpdateState.Idle else UpdateState.UpToDate
            } catch (e: Exception) {
                if (quiet) UpdateState.Idle else UpdateState.Error(e.message ?: "Update check failed")
            }
        }
    }

    private fun installUpdate(release: Release) {
        if (!Updater.canInstall(this)) {
            toast("Allow this app to install updates, then tap Install again")
            startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")),
            )
            return
        }
        lifecycleScope.launch {
            try {
                val apk = withContext(Dispatchers.IO) {
                    Updater.download(this@MainActivity, release) { p ->
                        runOnUiThread { updateState.value = UpdateState.Downloading(release, p) }
                    }
                }
                updateState.value = UpdateState.Installing
                withContext(Dispatchers.IO) { Updater.install(this@MainActivity, apk) }
            } catch (e: Exception) {
                updateState.value = UpdateState.Error(e.message ?: "Update failed")
            }
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}

private const val EXTRA_RUN_SELF_TEST = "run_self_test"

sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data object UpToDate : UpdateState
    data class Available(val release: Release) : UpdateState
    data class Downloading(val release: Release, val progress: Float) : UpdateState
    data object Installing : UpdateState
    data class Error(val message: String) : UpdateState
}
