package io.github.amandhakar.passkey.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.mutableStateOf
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.R
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.PasskeyProviderService
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.provider.verifyUser
import io.github.amandhakar.passkey.transfer.MovablePasskeys
import io.github.amandhakar.passkey.webauthn.Base64Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {
    private val providerEnabled = mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Used by the emulator test in CI (scripts/emulator_selftest.py); never in release builds.
        if (BuildConfig.SELF_TEST && savedInstanceState == null && intent.getBooleanExtra(EXTRA_RUN_SELF_TEST, false)) {
            lifecycleScope.launch { toast(SelfTest.run(this@MainActivity)) }
        }
        addScanShortcut()
        val store = PasskeyStore.get(this)
        setContent {
            PasskeyTheme {
                MainScreen(
                    passkeysFlow = store.passkeys,
                    problemsFlow = ProviderErrors.latest,
                    providerEnabled = providerEnabled.value,
                    versionName = BuildConfig.VERSION_NAME,
                    onOpenProviderSettings = ::openProviderSettings,
                    onScanQr = ::scanQr,
                    onSelfTest = { lifecycleScope.launch { toast(SelfTest.run(this@MainActivity)) } },
                    onDelete = ::deletePasskey,
                    onRename = { passkey, name -> store.rename(passkey.credentialId, name) },
                    onCopyProblems = ::copyProblems,
                    onClearProblems = { ProviderErrors.clear(this) },
                    onMovePasskeys = if (MovablePasskeys.ENABLED) ({ MovablePasskeys.open(this) }) else null,
                    onBackup = if (MovablePasskeys.ENABLED) ({ MovablePasskeys.openBackup(this) }) else null,
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        providerEnabled.value = isProviderEnabled()
        ProviderErrors.load(this)
        // GitHub build: re-wraps older movable passkeys under the fingerprint-only vault if the phone was just
        // unlocked (no prompt). Nothing to do in the store build.
        if (MovablePasskeys.ENABLED) {
            lifecycleScope.launch(Dispatchers.IO) { runCatching { MovablePasskeys.upgradeQuietly(this@MainActivity) } }
        }
    }

    /**
     * Long-pressing the app icon offers "Scan QR code", straight to the scanner for signing in on another
     * device. A dynamic shortcut, not a static one in XML, so it points at this build's own package (debug
     * builds have another). Launchers that don't support app shortcuts simply don't show it.
     */
    private fun addScanShortcut() {
        runCatching {
            val shortcut = ShortcutInfo.Builder(this, SHORTCUT_SCAN)
                .setShortLabel("Scan QR code")
                .setLongLabel("Scan a passkey QR code")
                .setIcon(Icon.createWithResource(this, R.drawable.ic_shortcut_scan))
                .setIntent(Intent(this, ScanQrActivity::class.java).setAction(Intent.ACTION_VIEW))
                .build()
            getSystemService(ShortcutManager::class.java)?.setDynamicShortcuts(listOf(shortcut))
        }
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

    /** Cross-device sign-in: scan the computer's passkey QR code (see [PasskeyQr]). */
    private fun scanQr() = PasskeyQr.scan(this)

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

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}

private const val EXTRA_RUN_SELF_TEST = "run_self_test"
private const val SHORTCUT_SCAN = "scan_qr"
