package io.github.amandhakar.passkey.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.amandhakar.passkey.webauthn.Base64Url
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Passkey private keys live in the Android Keystore (StrongBox when available). They never leave the
 * secure hardware, and each signature needs its own biometric or device PIN/pattern/password prompt:
 * the Keystore only signs with a [Signature] object that a prompt has authorised (see [signer]).
 *
 * Keys made by app 1.3.5 and older instead work for 30 seconds after any user
 * authentication; [isTimeBound] tells them apart. Their public keys are registered with sites, so they
 * cannot be converted, only replaced by making a new passkey.
 */
object PasskeyKeys {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /** 0 = authorise every operation separately, never for a time window. */
    private const val AUTH_PER_OPERATION = 0

    private fun alias(credentialId: ByteArray) = "passkey_" + Base64Url.encode(credentialId)

    private fun keyStore() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun privateKey(credentialId: ByteArray): PrivateKey =
        keyStore().getKey(alias(credentialId), null) as? PrivateKey
            ?: throw IllegalStateException("The key for this passkey is missing")

    fun generate(credentialId: ByteArray): ECPublicKey =
        try {
            generate(credentialId, strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(credentialId, strongBox = false)
        } catch (_: ProviderException) {
            // Some StrongBox chips claim support but reject this key configuration; use the TEE instead.
            generate(credentialId, strongBox = false)
        }

    private fun generate(credentialId: ByteArray, strongBox: Boolean): ECPublicKey {
        val spec = KeyGenParameterSpec.Builder(alias(credentialId), KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                AUTH_PER_OPERATION,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            // Adding a new fingerprint must not silently destroy every passkey.
            .setInvalidatedByBiometricEnrollment(false)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(spec)
        return generator.generateKeyPair().public as ECPublicKey
    }

    /** True for an older key that works for 30 s after any authentication instead of once per prompt. */
    fun isTimeBound(credentialId: ByteArray): Boolean {
        val key = privateKey(credentialId)
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        return info.userAuthenticationValidityDurationSeconds > 0
    }

    /**
     * An ES256 signer for this passkey. For a per-operation key, pass it to a biometric prompt as its
     * CryptoObject; it can sign once the prompt succeeds. For a time-bound key, call this after a prompt
     * (it throws UserNotAuthenticatedException otherwise).
     */
    fun signer(credentialId: ByteArray): Signature =
        Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey(credentialId)) }

    /** ES256 signature, ASN.1 DER encoded as WebAuthn expects, with a signer a prompt has unlocked. */
    fun sign(signer: Signature, data: ByteArray): ByteArray = signer.run {
        update(data)
        sign()
    }

    /** The public key, for checking signatures (the self-test uses it to verify a sign-in). */
    fun publicKey(credentialId: ByteArray): PublicKey? = keyStore().getCertificate(alias(credentialId))?.publicKey

    fun delete(credentialId: ByteArray) {
        keyStore().deleteEntry(alias(credentialId))
    }
}
