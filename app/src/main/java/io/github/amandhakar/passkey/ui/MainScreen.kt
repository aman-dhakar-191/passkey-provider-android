package io.github.amandhakar.passkey.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.unit.dp
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyGroups
import io.github.amandhakar.passkey.update.Release
import kotlinx.coroutines.flow.StateFlow
import java.text.DateFormat
import java.util.Date

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
    val problems by problemsFlow.collectAsState()
    var pendingDelete by remember { mutableStateOf<Passkey?>(null) }
    var pendingRename by remember { mutableStateOf<Passkey?>(null) }
    var query by remember { mutableStateOf("") }
    val groups = remember(passkeys, query) { PasskeyGroups.of(passkeys, query) }

    Scaffold(topBar = { TopAppBar(title = { Text("Passkey Vault") }) }) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding() + 8.dp,
                bottom = padding.calculateBottomPadding() + 16.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { ProviderCard(providerEnabled, onOpenProviderSettings, onSelfTest) }
            problems?.let { text -> item { ProblemsCard(text, onCopyProblems, onClearProblems) } }
            item { CrossDeviceCard(onScanQr) }
            if (updatesEnabled) item { UpdateCard(updateState, versionName, onCheckUpdate, onInstallUpdate) }
            item {
                Text(
                    "Saved passkeys (${passkeys.size})",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            if (passkeys.isEmpty()) {
                item {
                    Text(
                        "No passkeys yet. When a website or app offers to create a passkey, choose this app.",
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
                    Column(Modifier.padding(top = 4.dp)) {
                        Text(group.title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
                        if (group.title != group.rpId) Text(group.rpId, style = MaterialTheme.typography.bodySmall)
                    }
                }
                items(group.passkeys, key = { it.credentialId }) { passkey ->
                    PasskeyRow(passkey, onRename = { pendingRename = passkey }, onDelete = { pendingDelete = passkey })
                }
            }
        }
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
private fun ProviderCard(enabled: Boolean, onOpenSettings: () -> Unit, onSelfTest: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                if (enabled) "Passkey provider is on" else "Passkey provider is off",
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                if (enabled) "Apps and browsers on this phone can create and use passkeys stored here."
                else "Turn this app on under Passwords, passkeys & accounts so apps and browsers can use it.",
                style = MaterialTheme.typography.bodyMedium,
            )
            // Always shown: this is where the user picks the preferred passkey service, and that page is
            // hard to find in Settings (its name and place differ between phone makers).
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onOpenSettings) { Text("Passkey settings") }
                if (BuildConfig.DEBUG) OutlinedButton(onClick = onSelfTest) { Text("Test passkey") }
            }
        }
    }
}

@Composable
private fun ProblemsCard(text: String, onCopy: () -> Unit, onClear: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Passkey activity log", style = MaterialTheme.typography.titleMedium)
            Text(
                text.lineSequence().take(4).joinToString("\n"),
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onCopy) { Text("Copy details") }
                OutlinedButton(onClick = onClear) { Text("Clear") }
            }
        }
    }
}

@Composable
private fun CrossDeviceCard(onScanQr: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Sign in on a computer", style = MaterialTheme.typography.titleMedium)
            Text(
                "On the computer choose \"Use a phone or tablet\", then scan the QR code. " +
                    "Keep Bluetooth on - the phone must be near the computer.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(onClick = onScanQr) { Text("Scan QR code") }
        }
    }
}

@Composable
private fun UpdateCard(
    state: UpdateState,
    versionName: String,
    onCheck: () -> Unit,
    onInstall: (Release) -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("App version $versionName", style = MaterialTheme.typography.titleMedium)
            when (state) {
                UpdateState.Idle -> OutlinedButton(onClick = onCheck) { Text("Check for updates") }
                UpdateState.Checking -> Text("Checking...")
                UpdateState.UpToDate -> {
                    Text("You have the latest version.")
                    OutlinedButton(onClick = onCheck) { Text("Check again") }
                }
                is UpdateState.Available -> {
                    Text("Version ${state.release.version} is available.")
                    if (state.release.notes.isNotBlank()) {
                        Text(state.release.notes.take(500), style = MaterialTheme.typography.bodySmall)
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
}

@Composable
private fun PasskeyRow(passkey: Passkey, onRename: () -> Unit, onDelete: () -> Unit) {
    val date = remember(passkey.lastUsedAt) { DateFormat.getDateInstance().format(Date(passkey.lastUsedAt)) }
    val account = passkey.userName.ifBlank { passkey.displayName }
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(start = 16.dp, top = 12.dp, bottom = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(passkey.label.ifBlank { account }, style = MaterialTheme.typography.titleSmall)
                if (passkey.label.isNotBlank()) Text(account, style = MaterialTheme.typography.bodyMedium)
                Text("Last used $date", style = MaterialTheme.typography.bodySmall)
            }
            IconButton(onClick = onRename) { Icon(Icons.Default.Edit, contentDescription = "Rename passkey") }
            IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, contentDescription = "Delete passkey") }
        }
    }
}
