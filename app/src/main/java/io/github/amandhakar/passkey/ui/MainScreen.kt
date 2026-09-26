package io.github.amandhakar.passkey.ui

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyGroups
import io.github.amandhakar.passkey.update.Release
import kotlinx.coroutines.flow.StateFlow
import java.text.DateFormat
import java.util.Date

/**
 * Passkeys first. The provider status is one line (a card only when it needs action); the activity log,
 * settings shortcut and version/updates live in the top-bar menu; banners appear only when something
 * needs attention (last request failed, update available).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    passkeysFlow: StateFlow<List<Passkey>>,
    problemsFlow: StateFlow<String?>,
    providerEnabled: Boolean,
    updateState: UpdateState,
    updatesEnabled: Boolean,
    versionName: String,
    onOpenProviderSettings: () -> Unit,
    onScanQr: () -> Unit,
    onSelfTest: () -> Unit,
    onDelete: (Passkey) -> Unit,
    onRename: (Passkey, String) -> Unit,
    onCheckUpdate: () -> Unit,
    onInstallUpdate: (Release) -> Unit,
    onCopyProblems: () -> Unit,
    onClearProblems: () -> Unit,
) {
    val passkeys by passkeysFlow.collectAsState()
    val log by problemsFlow.collectAsState()
    var pendingDelete by remember { mutableStateOf<Passkey?>(null) }
    var pendingRename by remember { mutableStateOf<Passkey?>(null) }
    var query by remember { mutableStateOf("") }
    var menuOpen by remember { mutableStateOf(false) }
    var showLog by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    val groups = remember(passkeys, query) { PasskeyGroups.of(passkeys, query) }
    val lastEntry = log?.substringBefore("\n----------")
    val lastFailed = lastEntry?.contains("FAILED") == true
    val updateNeedsAttention = updateState is UpdateState.Available || updateState is UpdateState.Downloading ||
        updateState is UpdateState.Installing

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Passkey Vault") },
                actions = {
                    IconButton(onClick = { menuOpen = true }) { Icon(Icons.Default.MoreVert, contentDescription = "Menu") }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text("Passkey settings") },
                            onClick = { menuOpen = false; onOpenProviderSettings() },
                        )
                        DropdownMenuItem(text = { Text("Activity log") }, onClick = { menuOpen = false; showLog = true })
                        DropdownMenuItem(
                            text = { Text(if (updatesEnabled) "About & updates" else "About") },
                            onClick = { menuOpen = false; showAbout = true },
                        )
                        if (BuildConfig.SELF_TEST) {
                            DropdownMenuItem(text = { Text("Test passkey") }, onClick = { menuOpen = false; onSelfTest() })
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(onClick = onScanQr) { Text("Scan QR code") }
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding(),
                bottom = padding.calculateBottomPadding() + 88.dp, // room for the floating button
            ),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { ProviderStatus(providerEnabled, onOpenProviderSettings) }
            if (lastFailed) {
                item {
                    Banner(
                        text = "The last passkey request failed.",
                        action = "View log",
                        onAction = { showLog = true },
                    )
                }
            }
            if (updatesEnabled && updateNeedsAttention) {
                item { UpdatePanel(updateState, versionName, onCheckUpdate, onInstallUpdate) }
            }
            item {
                Text(
                    "Passkeys (${passkeys.size})",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            if (passkeys.isEmpty()) {
                item {
                    Text(
                        "No passkeys yet. When a website or app offers to create a passkey, choose Passkey Vault. " +
                            "To sign in on a computer, choose \"Use a phone or tablet\" there and scan the QR code.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            } else if (passkeys.size > 3) {
                item {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                        placeholder = { Text("Search sites, accounts and names") },
                    )
                }
                if (groups.isEmpty()) item { Text("No passkeys match \"$query\".") }
            }
            groups.forEach { group ->
                item(key = "site:${group.rpId}") {
                    Column(Modifier.padding(top = 6.dp)) {
                        Text(group.title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
                        if (group.title != group.rpId) {
                            Text(
                                group.rpId,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                items(group.passkeys, key = { it.credentialId }) { passkey ->
                    PasskeyRow(passkey, onRename = { pendingRename = passkey }, onDelete = { pendingDelete = passkey })
                }
            }
        }
    }

    if (showLog) {
        AlertDialog(
            onDismissRequest = { showLog = false },
            title = { Text("Activity log") },
            text = {
                Text(
                    log ?: if (BuildConfig.LOG_ALL_REQUESTS) {
                        "Nothing yet. Passkey requests from apps and browsers are recorded here."
                    } else {
                        "Nothing yet. If a passkey request goes wrong, the details are kept here so you can copy " +
                            "them for support. Successful sign-ins aren't recorded."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
                )
            },
            confirmButton = {
                if (log != null) TextButton(onClick = onCopyProblems) { Text("Copy") }
            },
            dismissButton = {
                Row {
                    if (log != null) TextButton(onClick = { onClearProblems(); showLog = false }) { Text("Clear") }
                    TextButton(onClick = { showLog = false }) { Text("Close") }
                }
            },
        )
    }

    if (showAbout) {
        val uriHandler = LocalUriHandler.current
        val context = LocalContext.current
        // openUri throws if nothing on the phone can open the link (e.g. no email app).
        val open: (String) -> Unit = { uri ->
            runCatching { uriHandler.openUri(uri) }
                .onFailure { Toast.makeText(context, "No app to open $uri", Toast.LENGTH_LONG).show() }
        }
        AlertDialog(
            onDismissRequest = { showAbout = false },
            title = { Text("Passkey Vault") },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                ) {
                    Text(
                        "Sign in with your fingerprint instead of a password. Your keys never leave this phone " +
                            "and aren't backed up, so keep another way to sign in to important accounts.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    AboutLink(Icons.Filled.Lock, "Privacy policy") { open(Links.PRIVACY) }
                    AboutLink(Icons.Filled.Info, "Terms of use") { open(Links.TERMS) }
                    AboutLink(Icons.Filled.Home, "Website") { open(Links.WEBSITE) }
                    AboutLink(Icons.Filled.Email, "Contact support") { open("mailto:${Links.SUPPORT_EMAIL}") }
                    AboutLink(Icons.Filled.Build, "Source code (Apache License 2.0)") { open(Links.SOURCE) }
                    Text(
                        "Version $versionName · Made by Aman Dhakar",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                    if (updatesEnabled) UpdatePanel(updateState, versionName, onCheckUpdate, onInstallUpdate, inDialog = true)
                }
            },
            confirmButton = { TextButton(onClick = { showAbout = false }) { Text("Close") } },
        )
    }

    pendingRename?.let { passkey ->
        var name by remember(passkey.credentialId) { mutableStateOf(passkey.label) }
        AlertDialog(
            onDismissRequest = { pendingRename = null },
            title = { Text("Name this passkey") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "${passkey.userName.ifBlank { passkey.displayName }} on ${passkey.rpId}. " +
                            "The name is only shown on this phone.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it.take(60) },
                        singleLine = true,
                        placeholder = { Text("e.g. Work account") },
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { pendingRename = null; onRename(passkey, name) }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { pendingRename = null }) { Text("Cancel") } },
        )
    }

    pendingDelete?.let { passkey ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Delete passkey?") },
            text = {
                Text(
                    "You will no longer be able to sign in to ${passkey.rpId} as ${passkey.userName} " +
                        "with this passkey. This cannot be undone.",
                )
            },
            confirmButton = {
                TextButton(onClick = { pendingDelete = null; onDelete(passkey) }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun AboutLink(icon: ImageVector, label: String, onClick: () -> Unit) {
    TextButton(onClick = onClick, contentPadding = PaddingValues(horizontal = 4.dp, vertical = 8.dp)) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(12.dp))
        Text(label, modifier = Modifier.weight(1f))
    }
}

/** One quiet line when all is well; a card with the fix when the provider is off. */
@Composable
private fun ProviderStatus(enabled: Boolean, onOpenSettings: () -> Unit) {
    if (enabled) {
        Row(
            Modifier.fillMaxWidth().padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Text(
                "Passkey Vault is active for apps and browsers",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
        }
        return
    }
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                "Passkey Vault is turned off",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                "Turn it on and choose it as the preferred service under Passwords, passkeys & accounts, " +
                    "so apps and browsers can use it.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Button(onClick = onOpenSettings) { Text("Open settings") }
        }
    }
}

@Composable
private fun Banner(text: String, action: String, onAction: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 4.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.onErrorContainer)
            Text(
                text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.weight(1f).padding(horizontal = 12.dp),
            )
            TextButton(onClick = onAction) { Text(action) }
        }
    }
}

@Composable
private fun UpdatePanel(
    state: UpdateState,
    versionName: String,
    onCheck: () -> Unit,
    onInstall: (Release) -> Unit,
    inDialog: Boolean = false,
) {
    val content = @Composable {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            when (state) {
                UpdateState.Idle -> OutlinedButton(onClick = onCheck) { Text("Check for updates") }
                UpdateState.Checking -> Text("Checking for updates...")
                UpdateState.UpToDate -> {
                    Text("You have the latest version ($versionName).")
                    OutlinedButton(onClick = onCheck) { Text("Check again") }
                }
                is UpdateState.Available -> {
                    Text("Version ${state.release.version} is available.", style = MaterialTheme.typography.titleSmall)
                    if (state.release.notes.isNotBlank()) {
                        Text(state.release.notes.take(300), style = MaterialTheme.typography.bodySmall)
                    }
                    Button(onClick = { onInstall(state.release) }) { Text("Download and install") }
                }
                is UpdateState.Downloading -> {
                    Text("Downloading ${state.release.version}... ${(state.progress * 100).toInt()}%")
                    LinearProgressIndicator(progress = { state.progress }, modifier = Modifier.fillMaxWidth())
                }
                UpdateState.Installing -> Text("Installing...")
                is UpdateState.Error -> {
                    Text(state.message, color = MaterialTheme.colorScheme.error)
                    OutlinedButton(onClick = onCheck) { Text("Try again") }
                }
            }
        }
    }
    if (inDialog) {
        content()
    } else {
        Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp)) { content() } }
    }
}

@Composable
private fun PasskeyRow(passkey: Passkey, onRename: () -> Unit, onDelete: () -> Unit) {
    val date = remember(passkey.lastUsedAt) { DateFormat.getDateInstance().format(Date(passkey.lastUsedAt)) }
    val account = passkey.userName.ifBlank { passkey.displayName }
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(start = 16.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(passkey.label.ifBlank { account }, style = MaterialTheme.typography.titleSmall)
                if (passkey.label.isNotBlank()) Text(account, style = MaterialTheme.typography.bodyMedium)
                Text(
                    "Last used $date",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = onRename) { Icon(Icons.Default.Edit, contentDescription = "Rename passkey") }
            IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, contentDescription = "Delete passkey") }
        }
    }
}
