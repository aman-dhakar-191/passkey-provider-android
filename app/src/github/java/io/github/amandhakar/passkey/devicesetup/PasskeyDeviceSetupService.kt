package io.github.amandhakar.passkey.devicesetup

import android.util.Log
import androidx.core.os.OutcomeReceiverCompat
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.providerevents.exception.ExportCredentialsException
import androidx.credentials.providerevents.exception.ExportCredentialsInvalidJsonException
import androidx.credentials.providerevents.exception.GetCredentialTransferCapabilitiesException
import androidx.credentials.providerevents.exception.GetCredentialTransferCapabilitiesUnknownErrorException
import androidx.credentials.providerevents.exception.ImportCredentialsException
import androidx.credentials.providerevents.exception.ImportCredentialsUnknownErrorException
import androidx.credentials.providerevents.service.DeviceSetupService
import androidx.credentials.providerevents.transfer.CredentialTransferCapabilities
import androidx.credentials.providerevents.transfer.CredentialTransferCapabilitiesRequest
import androidx.credentials.providerevents.transfer.CredentialTypes
import androidx.credentials.providerevents.transfer.ExportCredentialsRequest
import androidx.credentials.providerevents.transfer.ExportCredentialsResponse
import androidx.credentials.providerevents.transfer.ImportCredentialsRequest
import androidx.credentials.providerevents.transfer.ImportCredentialsResponse
import androidx.credentials.providerevents.transfer.PerTypeExportResult
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.LogText
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.webauthn.Base64Url
import java.util.concurrent.Executors

/**
 * BETA (GitHub builds only): Android's device-setup credential transfer, built to observe what Android sends
 * during "copy apps & data" from an old phone to a new one. It reports honestly and changes nothing: no
 * passkey is created, deleted, exported or stored by this service.
 *
 * ## Who calls this, and the (inverted) names
 *
 * Google Play services drives device setup and is the only caller: the androidx library rejects any other
 * app (it checks the caller is Play services' UID before any method here runs). The method names are from
 * the *system's* point of view:
 *  - [onGetCredentialTransferCapabilities], on the OLD phone: "how many credentials could you transfer?"
 *    Shown to the user during setup.
 *  - [onImportCredentialsRequest], on the OLD phone: the system imports FROM us. We return a CXF document.
 *  - [onExportCredentialsRequest], on the NEW phone: the system exports INTO us a CXF document from the
 *    old phone. We report per type how many we stored, failed or ignored.
 * Calls only arrive while Passkey Vault is enabled as a passkey service in Settings on that phone.
 *
 * ## Export flow (old phone)
 *
 * Each passkey's private key was generated inside the Android Keystore (StrongBox or the TEE) as
 * non-exportable, with user authentication required. CXF needs that private key as PKCS#8 bytes (see
 * [Cxf]), and the Keystore will never give them out; that is the security guarantee the app is built on,
 * not a limitation to work around. So every passkey is reported as not transferable, capabilities say 0,
 * and the returned CXF document holds no accounts. The log lists each passkey's key storage and why it was
 * left out.
 *
 * ## Import flow (new phone)
 *
 * The delivered document is outlined in the log (structure and sizes only) and each passkey is checked for
 * the fields a real import would need. Nothing is stored: a real import would have to put a private key
 * that arrived in memory into the Keystore, which this beta doesn't do. Every passkey is therefore
 * reported as ignored, never as a success.
 *
 * ## Who protects what
 *
 *  - Android / Play services: authenticating both phones, pairing them, and encrypting the transfer
 *    between them; checking the caller of this service; the file hand-off (a content URI the library
 *    reads/writes).
 *  - This provider: deciding what may leave the phone (here: nothing, since keys are hardware-bound),
 *    never logging credential material, validating what arrives, and, in a real import, protecting received
 *    private keys (Keystore import, user authentication) and wiping them from memory.
 */
class PasskeyDeviceSetupService : DeviceSetupService() {
    // Keystore and file work stays off the main thread, where the library delivers these calls.
    private val worker = Executors.newSingleThreadExecutor()

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    override fun onGetCredentialTransferCapabilities(
        request: CredentialTransferCapabilitiesRequest,
        callingAppInfo: CallingAppInfo,
        callback: OutcomeReceiverCompat<CredentialTransferCapabilities, GetCredentialTransferCapabilitiesException>,
    ) = handle("capabilities", { callback.onError(GetCredentialTransferCapabilitiesUnknownErrorException(it)) }) {
        log("Transfer capabilities requested (old phone)", caller(callingAppInfo), types(request.credentialTypes, request.knownExtensions))
        val report = exportReport()
        log(report.lines)
        val size = empty().toByteArray().size.toLong()
        log("Answered: 0 transferable (${report.held} held, all hardware-bound), $size bytes")
        callback.onResult(CredentialTransferCapabilities(0, 0, 0, size))
    }

    override fun onImportCredentialsRequest(
        request: ImportCredentialsRequest,
        callingAppInfo: CallingAppInfo,
        callback: OutcomeReceiverCompat<ImportCredentialsResponse, ImportCredentialsException>,
    ) = handle("import request", { callback.onError(ImportCredentialsUnknownErrorException(it)) }) {
        log("Credentials requested from this phone (old phone)", caller(callingAppInfo), types(request.credentialTypes, request.knownExtensions))
        if (CredentialTypes.CREDENTIAL_TYPE_PUBLIC_KEY !in request.credentialTypes) log("Passkeys were not requested")
        val report = exportReport()
        log(report.lines)
        val document = empty()
        log(listOf("Returned CXF document: 0 passkeys (${report.held} left out, keys can't leave this phone)") + Cxf.outline(document, LogText::site))
        callback.onResult(ImportCredentialsResponse(document))
    }

    override fun onExportCredentialsRequest(
        request: ExportCredentialsRequest,
        callingAppInfo: CallingAppInfo,
        callback: OutcomeReceiverCompat<ExportCredentialsResponse, ExportCredentialsException>,
    ) = handle("export request", { callback.onError(ExportCredentialsInvalidJsonException(it)) }) {
        log("Credentials delivered to this phone (new phone)", caller(callingAppInfo), "${request.credentialsJson.length} characters of CXF")
        log(listOf("Delivered document outline:") + Cxf.outline(request.credentialsJson, LogText::site))
        val delivered = Cxf.read(request.credentialsJson)
        val lines = mutableListOf(
            "CXF version ${delivered.version}: ${delivered.accounts} account(s), ${delivered.items} item(s), " +
                "${delivered.passkeys.size} passkey(s), other types ${delivered.otherCredentials}",
        )
        delivered.passkeys.forEachIndexed { i, p ->
            lines += "Passkey ${i + 1}: ${LogText.site(p.rpId)}, credential ID ${yes(p.hasCredentialId)}, user handle ${yes(p.hasUserHandle)}, " +
                "key ${p.keyBytes?.let { "$it bytes" } ?: "missing"}${if (p.keyLooksLikePkcs8) " (PKCS#8 shape)" else ""} → " +
                if (p.complete) "importable in principle; NOT stored (beta)" else "incomplete, can't be imported"
        }
        log(lines)
        val results = buildMap {
            if (delivered.passkeys.isNotEmpty()) {
                val incomplete = delivered.passkeys.count { !it.complete }
                // Complete passkeys are "ignored" (not stored by this beta), incomplete ones "failed" (invalid).
                put(Cxf.TYPE_PASSKEY, PerTypeExportResult(Cxf.TYPE_PASSKEY, 0, incomplete, delivered.passkeys.size - incomplete))
            }
            delivered.otherCredentials.forEach { (type, n) -> put(type, PerTypeExportResult(type, 0, 0, n)) }
        }
        log("Answered: 0 stored; " + results.values.joinToString { "${it.credentialType}: ${it.numFailure} failed, ${it.numIgnored} ignored" }.ifEmpty { "nothing to store" })
        callback.onResult(ExportCredentialsResponse(results))
    }

    private class ExportReport(val held: Int, val lines: List<String>)

    /** Checks each saved passkey's key storage. Reads metadata only; see [PasskeyKeys.storage]. */
    private fun exportReport(): ExportReport {
        val passkeys = PasskeyStore.get(this).all()
        val lines = mutableListOf("${passkeys.size} passkey(s) on this phone:")
        passkeys.forEachIndexed { i, p ->
            val storage = runCatching { PasskeyKeys.storage(Base64Url.decode(p.credentialId)) }
            val where = storage.fold(
                { it?.let { s -> "${s.securityLevel}, user auth ${yes(s.userAuthRequired)}, exportable ${yes(s.exportable)}" } ?: "key missing" },
                { "key info unavailable (${it.javaClass.simpleName})" },
            )
            lines += "  ${i + 1}. ${LogText.site(p.rpId)}: $where → left out"
            if (i == 0) lines += "  CXF shape it would need: " + Cxf.passkeyOutline(
                LogText.site(p.rpId), p.credentialId.length, p.userId.length, storage.getOrNull()?.securityLevel ?: "Keystore",
            )
        }
        return ExportReport(passkeys.size, lines)
    }

    private fun empty() = Cxf.emptyExport(EXPORTER_RP_ID, "Passkey Vault", System.currentTimeMillis() / 1000)

    /** Runs [work] on the worker; any failure is logged and reported to Android, never swallowed. */
    private fun handle(what: String, fail: (String) -> Unit, work: () -> Unit) {
        worker.execute {
            try {
                work()
            } catch (e: Exception) {
                Log.e(TAG, "Device setup $what failed", e)
                ProviderErrors.problem(this, "Device setup (beta): $what failed: ${e.javaClass.simpleName}")
                fail("Passkey Vault could not handle the $what")
            }
        }
    }

    private fun caller(info: CallingAppInfo) = "caller ${LogText.field(info.packageName)}"

    private fun types(types: Set<String>, extensions: Set<String>) =
        "types ${types.map { LogText.field(it, 30) }.sorted()}, extensions ${extensions.map { LogText.field(it, 30) }.sorted()}"

    private fun yes(b: Boolean) = if (b) "yes" else "no"

    private fun log(vararg parts: String) = log(listOf(parts.joinToString(", ")))

    /** To logcat (tag [TAG], every line) and the in-app activity log (one entry, cut if long). */
    private fun log(lines: List<String>) {
        lines.forEach { Log.i(TAG, it) }
        ProviderErrors.note(this, "Device setup (beta): " + lines.joinToString("\n"))
    }

    private companion object {
        const val TAG = "PasskeyDeviceSetup"
        // CXF names the exporter by an RP ID (a domain); the app's website is the domain it controls.
        const val EXPORTER_RP_ID = "aman-dhakar-191.github.io"
    }
}
