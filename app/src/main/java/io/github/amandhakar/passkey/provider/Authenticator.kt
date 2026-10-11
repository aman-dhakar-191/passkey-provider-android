package io.github.amandhakar.passkey.provider

import android.content.Context
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.transfer.MovablePasskeys
import io.github.amandhakar.passkey.webauthn.AssertionOptions
import io.github.amandhakar.passkey.webauthn.Base64Url
import io.github.amandhakar.passkey.webauthn.CreationOptions
import io.github.amandhakar.passkey.webauthn.WebAuthnEncoding
import io.github.amandhakar.passkey.webauthn.WebAuthnJson
import java.security.SecureRandom
import java.security.Signature

/**
 * The WebAuthn authenticator. Callers must have verified the caller/RP ID and the user before calling.
 *
 * When a browser supplies [clientDataHash] it built clientDataJSON itself and only needs our signature
 * over that hash; the clientDataJSON we return is then ignored by the browser.
 */
class Authenticator(context: Context) {
    private val context = context.applicationContext
    private val store = PasskeyStore.get(context)

    // "none" attestation carries no signature, so registration never needs the client data hash.
    fun register(options: CreationOptions, rpId: String, origin: String): String {
        val credentialId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        // GitHub build setting: a movable passkey's key is made so it can later be sent to a new phone.
        val movable = MovablePasskeys.newPasskeysMovable(context)
        val (publicKey, wrappedKey) =
            if (movable) MovablePasskeys.createKey(context, credentialId) else PasskeyKeys.generate(credentialId) to ""
        val cose = WebAuthnEncoding.coseEs256PublicKey(
            WebAuthnEncoding.unsignedFixed(publicKey.w.affineX),
            WebAuthnEncoding.unsignedFixed(publicKey.w.affineY),
        )
        val authData = WebAuthnEncoding.authenticatorData(
            rpId = rpId,
            flags = backupFlags(movable, backedUp = false) or
                WebAuthnEncoding.FLAG_USER_PRESENT or WebAuthnEncoding.FLAG_USER_VERIFIED,
            signCount = 0,
            attestedCredentialData = WebAuthnEncoding.attestedCredentialData(credentialId, cose),
        )
        val clientData = WebAuthnEncoding.clientDataJson("webauthn.create", options.challenge, origin)

        val now = System.currentTimeMillis()
        val replaced = store.add(
            Passkey(
                credentialId = Base64Url.encode(credentialId),
                rpId = rpId,
                rpName = options.rpName.ifBlank { rpId },
                userId = Base64Url.encode(options.userId),
                userName = options.userName,
                displayName = options.userDisplayName,
                createdAt = now,
                lastUsedAt = now,
                movable = movable,
                wrappedKey = wrappedKey,
            ),
        )
        replaced.forEach { PasskeyKeys.delete(Base64Url.decode(it.credentialId)) }

        return WebAuthnJson.registrationResponse(
            credentialId = credentialId,
            clientDataJson = clientData,
            attestationObject = WebAuthnEncoding.noneAttestationObject(authData),
            authenticatorData = authData,
            subjectPublicKeyInfo = publicKey.encoded,
        )
    }

    /** Signs with [signer], which a user-verification prompt must already have unlocked (see PasskeyKeys.signer). */
    fun authenticate(
        passkey: Passkey,
        options: AssertionOptions,
        origin: String,
        clientDataHash: ByteArray?,
        signer: Signature,
    ): String {
        val credentialId = Base64Url.decode(passkey.credentialId)
        val authData = WebAuthnEncoding.authenticatorData(
            rpId = passkey.rpId,
            flags = backupFlags(passkey.movable, passkey.backedUp) or
                WebAuthnEncoding.FLAG_USER_PRESENT or WebAuthnEncoding.FLAG_USER_VERIFIED,
            // Passkeys conventionally report 0: the RP must not expect a counter from a syncable-style credential.
            signCount = 0,
        )
        val clientData = WebAuthnEncoding.clientDataJson("webauthn.get", options.challenge, origin)
        val hash = clientDataHash ?: WebAuthnEncoding.sha256(clientData)
        val signature = PasskeyKeys.sign(signer, authData + hash)
        store.markUsed(passkey.credentialId, System.currentTimeMillis())
        return WebAuthnJson.authenticationResponse(
            credentialId = credentialId,
            clientDataJson = clientData,
            authenticatorData = authData,
            signature = signature,
            userHandle = Base64Url.decode(passkey.userId),
        )
    }

    /** WebAuthn backup flags: movable passkeys are "backup eligible", and "backed up" once a copy exists elsewhere. */
    private fun backupFlags(movable: Boolean, backedUp: Boolean): Int =
        (if (movable) WebAuthnEncoding.FLAG_BACKUP_ELIGIBLE else 0) or
            (if (movable && backedUp) WebAuthnEncoding.FLAG_BACKED_UP else 0)
}
