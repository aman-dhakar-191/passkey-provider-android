package io.github.amandhakar.passkeydemo

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import kotlin.coroutines.cancellation.CancellationException

class MainActivity : ComponentActivity() {
    private val reports = mutableStateListOf<Report>()
    private val busy = mutableStateOf(false)
    private val known = mutableStateOf(0)
    private val update = mutableStateOf<UpdateState>(UpdateState.Idle)
    private val random = SecureRandom()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        known.value = DemoStore.ids(this).size
        setContent {
            DemoTheme {
                DemoScreen(
                    reports = reports,
                    busy = busy.value,
                    known = known.value,
                    update = update.value,
                    fingerprint = remember { runCatching { AppIdentity.fingerprint(this) }.getOrElse { "unknown: ${it.message}" } },
                    onCreate = { name, exclude -> run("Create passkey") { createPasskey(name, exclude) } },
                    onSignIn = { run("Sign in") { signIn() } },
                    onCheckSite = { run("Site setup") { checkSite() } },
                    onCopySetup = { copy("assetlinks.json", AssetLinks.file(BuildConfig.APPLICATION_ID, AppIdentity.fingerprint(this))) },
                    onCopyResults = { copy("Passkey demo results", reports.joinToString("\n\n") { it.toText() }) },
                    onClear = { reports.clear() },
                    onForget = { DemoStore.clear(this); known.value = 0 },
                    onOpenWeb = { url -> startActivity(Intent(this, WebLoginActivity::class.java).apply { url?.let { putExtra(WebLoginActivity.EXTRA_URL, it) } }) },
                    onOpenBrowser = { url -> openInBrowser(url) },
                    onCheckUpdate = { checkForUpdate() },
                    onInstall = { installUpdate(it) },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        known.value = DemoStore.ids(this).size // the web page may have added one
    }

    private fun randomBytes(size: Int) = ByteArray(size).also(random::nextBytes)

    private fun run(title: String, block: suspend () -> Report) {
        if (busy.value) return
        busy.value = true
        lifecycleScope.launch {
            val report = try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Report(title, listOf(Check("Ran without an unexpected error", false, "${e.javaClass.simpleName}: ${e.message}")))
            }
            reports.add(0, report)
            known.value = DemoStore.ids(this@MainActivity).size
            busy.value = false
        }
    }

    private suspend fun createPasskey(userName: String, excludeExisting: Boolean): Report {
        val title = if (excludeExisting) "Create passkey, excluding existing ones" else "Create passkey"
        val challenge = randomBytes(32)
        val userId = PasskeyVerifier.sha256(userName.toByteArray()).copyOf(16)
        val request = JSONObject()
            .put("rp", JSONObject().put("id", BuildConfig.RP_ID).put("name", "Passkey demo"))
            .put("user", JSONObject().put("id", PasskeyVerifier.b64u(userId)).put("name", userName).put("displayName", userName))
            .put("challenge", PasskeyVerifier.b64u(challenge))
            .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
            .put("attestation", "none")
            .put("timeout", 120_000)
        val existing = DemoStore.ids(this)
        if (excludeExisting) {
            request.put(
                "excludeCredentials",
                JSONArray().also { array -> existing.forEach { array.put(JSONObject().put("type", "public-key").put("id", it)) } },
            )
        }
        val response = try {
            val result = CredentialManager.create(this).createCredential(this, CreatePublicKeyCredentialRequest(request.toString()))
            (result as CreatePublicKeyCredentialResponse).registrationResponseJson
        } catch (e: CreatePublicKeyCredentialDomException) {
            if (e.domError is InvalidStateError) {
                return Report(
                    title,
                    listOf(Check("Provider refused: 'already registered' (InvalidStateError)", excludeExisting && existing.isNotEmpty(), "That is the right answer only when an excluded passkey exists here (${existing.size} known).")),
                )
            }
            return failure(title, e)
        } catch (e: CreateCredentialCancellationException) {
            return Report(title, listOf(Check("Not cancelled", false, "You cancelled.")))
        } catch (e: CreateCredentialNoCreateOptionException) {
            return Report(title, listOf(Check("A passkey provider offered to save it", false, "Nothing offered. Is Passkey Vault switched on in Settings > Passwords, passkeys & accounts?")))
        } catch (e: CreateCredentialException) {
            return failure(title, e)
        }
        val registration = PasskeyVerifier.verifyRegistration(BuildConfig.RP_ID, challenge, response, AppIdentity.origin(this))
        if (registration.ok) DemoStore.save(this, registration.credentialId.orEmpty(), registration.publicKey ?: byteArrayOf(), userName, "native")
        return Report(title, registration.checks)
    }

    private suspend fun signIn(): Report {
        val title = "Sign in with a passkey"
        val challenge = randomBytes(32)
        val request = JSONObject()
            .put("rpId", BuildConfig.RP_ID)
            .put("challenge", PasskeyVerifier.b64u(challenge))
            .put("userVerification", "required")
            .put("timeout", 120_000)
        val response = try {
            val result = CredentialManager.create(this).getCredential(this, GetCredentialRequest(listOf(GetPublicKeyCredentialOption(request.toString()))))
            (result.credential as? PublicKeyCredential)?.authenticationResponseJson
                ?: return Report(title, listOf(Check("Android returned a passkey", false, "got ${result.credential.type}")))
        } catch (e: NoCredentialException) {
            return Report(title, listOf(Check("A passkey was offered", false, "None offered: create one first, or the provider refused because ${BuildConfig.RP_ID} does not vouch for this app (run 'Check site setup', and see Passkey Vault's activity log).")))
        } catch (e: GetCredentialCancellationException) {
            return Report(title, listOf(Check("Not cancelled", false, "You cancelled.")))
        } catch (e: GetCredentialException) {
            return failure(title, e)
        }
        val checks = PasskeyVerifier.verifySignIn(BuildConfig.RP_ID, challenge, response, AppIdentity.origin(this)) { DemoStore.publicKey(this, it) }
        return Report(title, checks)
    }

    private fun failure(title: String, e: Exception) = Report(
        title,
        listOf(Check("Android and the provider completed the request", false, "${e.javaClass.simpleName} (${(e as? CreateCredentialException)?.type ?: (e as? GetCredentialException)?.type}): ${e.message}")),
        "Open Passkey Vault's activity log (menu, top right) for what it refused and why.",
    )

    private suspend fun checkSite(): Report {
        val url = "https://${BuildConfig.RP_ID}/.well-known/assetlinks.json"
        val fingerprint = AppIdentity.fingerprint(this)
        val (status, body) = withContext(Dispatchers.IO) {
            try {
                val conn = URL(url).openConnection() as HttpURLConnection
                try {
                    conn.instanceFollowRedirects = false // Digital Asset Links forbids redirects
                    conn.connectTimeout = 10_000
                    conn.readTimeout = 10_000
                    val code = conn.responseCode
                    code to if (code == 200) conn.inputStream.use { it.readBytes().take(512 * 1024).toByteArray().toString(Charsets.UTF_8) } else null
                } finally {
                    conn.disconnect()
                }
            } catch (e: Exception) {
                null to "${e.javaClass.simpleName}: ${e.message}"
            }
        }
        return Report("Site setup for ${BuildConfig.RP_ID}", AssetLinks.analyze(status, body, BuildConfig.APPLICATION_ID, fingerprint), "Checked $url")
    }

    private fun copy(label: String, text: String) {
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(label, text))
        Toast.makeText(this, "Copied: $label", Toast.LENGTH_SHORT).show()
    }

    private fun openInBrowser(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, "No browser found", Toast.LENGTH_SHORT).show()
        }
    }

    private fun checkForUpdate() {
        update.value = UpdateState.Checking
        lifecycleScope.launch {
            update.value = try {
                val release = withContext(Dispatchers.IO) { Updater.latestRelease() }
                when {
                    release == null -> UpdateState.Error("No demo release found in ${BuildConfig.UPDATE_REPO} yet")
                    Updater.isNewer(release) -> UpdateState.Available(release)
                    else -> UpdateState.UpToDate(release.version)
                }
            } catch (e: Exception) {
                UpdateState.Error(e.message ?: "Update check failed")
            }
        }
    }

    private fun installUpdate(release: Release) {
        if (!Updater.canInstall(this)) {
            Toast.makeText(this, "Allow this app to install updates, then tap Install again", Toast.LENGTH_LONG).show()
            startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")))
            return
        }
        lifecycleScope.launch {
            try {
                val apk = withContext(Dispatchers.IO) {
                    Updater.download(this@MainActivity, release) { p -> runOnUiThread { update.value = UpdateState.Downloading(release, p) } }
                }
                update.value = UpdateState.Installing
                withContext(Dispatchers.IO) { Updater.install(this@MainActivity, apk) }
            } catch (e: Exception) {
                update.value = UpdateState.Error(e.message ?: "Update failed")
            }
        }
    }
}

sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data class UpToDate(val version: String) : UpdateState
    data class Available(val release: Release) : UpdateState
    data class Downloading(val release: Release, val progress: Float) : UpdateState
    data object Installing : UpdateState
    data class Error(val message: String) : UpdateState
}

@Composable
private fun DemoTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context),
        content = content,
    )
}

@Composable
private fun DemoScreen(
    reports: List<Report>,
    busy: Boolean,
    known: Int,
    update: UpdateState,
    fingerprint: String,
    onCreate: (String, Boolean) -> Unit,
    onSignIn: () -> Unit,
    onCheckSite: () -> Unit,
    onCopySetup: () -> Unit,
    onCopyResults: () -> Unit,
    onClear: () -> Unit,
    onForget: () -> Unit,
    onOpenWeb: (String?) -> Unit,
    onOpenBrowser: (String) -> Unit,
    onCheckUpdate: () -> Unit,
    onInstall: (Release) -> Unit,
) {
    var userName by remember { mutableStateOf("demo-user") }
    var exclude by remember { mutableStateOf(false) }
    var webUrl by remember { mutableStateOf("https://webauthn.io") }
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
    Column(
        Modifier.systemBarsPadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Passkey demo", style = MaterialTheme.typography.headlineSmall)
        Text("Tries passkeys the way apps do, against whichever passkey provider you chose in Android settings (for example Passkey Vault). It plays the website: it checks every answer the way a real server must.", style = MaterialTheme.typography.bodyMedium)

        Section("This app and its site") {
            Text("Site (RP ID): ${BuildConfig.RP_ID}\nPackage: ${BuildConfig.APPLICATION_ID}\nSigning certificate SHA-256:\n$fingerprint\nVersion ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.bodySmall)
            Text("The provider only lets an app use a site's passkeys if that site's /.well-known/assetlinks.json names the app and its certificate.", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onCheckSite, enabled = !busy) { Text("Check site setup") }
                OutlinedButton(onClick = onCopySetup) { Text("Copy assetlinks.json") }
            }
        }

        Section("Native: passkeys inside this app") {
            OutlinedTextField(userName, { userName = it }, label = { Text("Username") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Switch(exclude, { exclude = it })
                Text("Exclude passkeys made here (should be refused)", style = MaterialTheme.typography.bodySmall)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { onCreate(userName.ifBlank { "demo-user" }, exclude) }, enabled = !busy) { Text("Create passkey") }
                Button(onClick = onSignIn, enabled = !busy) { Text("Sign in") }
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Passkeys made by this demo: $known", style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = onForget) { Text("Forget") }
            }
        }

        Section("Web page inside the app (WebView)") {
            Text("Like apps that show their login page as a web page. The demo site's own login page is checked here; any other page just shows what the passkey app did.", style = MaterialTheme.typography.bodySmall)
            Button(onClick = { onOpenWeb(null) }) { Text("Open the demo site's login page") }
            OutlinedTextField(webUrl, { webUrl = it }, label = { Text("Any other page") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { onOpenWeb(webUrl) }) { Text("In a WebView") }
                OutlinedButton(onClick = { onOpenBrowser(webUrl) }) { Text("In the browser") }
            }
        }

        Section("Updates") {
            when (update) {
                UpdateState.Idle -> Text("Version ${BuildConfig.VERSION_NAME}. Updates come from this repository's GitHub Releases.", style = MaterialTheme.typography.bodySmall)
                UpdateState.Checking -> Text("Checking...", style = MaterialTheme.typography.bodySmall)
                is UpdateState.UpToDate -> Text("Up to date (latest release is ${update.version}).", style = MaterialTheme.typography.bodySmall)
                is UpdateState.Available -> {
                    Text("Version ${update.release.version} is available.\n${update.release.notes.take(300)}", style = MaterialTheme.typography.bodySmall)
                    Button(onClick = { onInstall(update.release) }) { Text("Download and install ${update.release.version}") }
                }
                is UpdateState.Downloading -> Text("Downloading ${update.release.version}: ${(update.progress * 100).toInt()}%", style = MaterialTheme.typography.bodySmall)
                UpdateState.Installing -> Text("Installing...", style = MaterialTheme.typography.bodySmall)
                is UpdateState.Error -> Text(update.message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            OutlinedButton(onClick = onCheckUpdate, enabled = update !is UpdateState.Checking && update !is UpdateState.Downloading) { Text("Check for updates") }
        }

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Results", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = onCopyResults, enabled = reports.isNotEmpty()) { Text("Copy all") }
            OutlinedButton(onClick = onClear, enabled = reports.isNotEmpty()) { Text("Clear") }
        }
        if (busy) Text("Waiting for Android and the passkey provider...", style = MaterialTheme.typography.bodySmall)
        if (reports.isEmpty() && !busy) Text("Nothing yet.", style = MaterialTheme.typography.bodySmall)
        reports.forEach { ReportCard(it) }
    }
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            content()
        }
    }
}

@Composable
private fun ReportCard(report: Report) {
    val good = Color(0xFF15803D)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(report.title, style = MaterialTheme.typography.titleSmall)
            val failed = report.checks.count { !it.ok }
            Text(
                if (failed == 0) "All ${report.checks.size} checks passed" else "$failed of ${report.checks.size} checks failed",
                color = if (failed == 0) good else MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
            report.checks.forEach { check ->
                Text(
                    (if (check.ok) "✔ " else "✘ ") + check.name + if (check.detail.isNotBlank()) "\n     ${check.detail}" else "",
                    color = if (check.ok) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            report.note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}
