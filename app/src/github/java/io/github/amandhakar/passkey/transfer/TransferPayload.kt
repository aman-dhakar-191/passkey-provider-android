package io.github.amandhakar.passkey.transfer

import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.provider.OriginRules
import io.github.amandhakar.passkey.webauthn.Base64Url
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/** One passkey on its way to another phone: its details plus its key pair. */
internal class MovingPasskey(val passkey: Passkey, val publicKey: ByteArray, val privateKey: ByteArray)

/**
 * What the old phone sends over the secure channel: a JSON document with the passkeys and their keys.
 * Only ever travels inside the encrypted, QR-authenticated channel; never written to storage.
 */
internal object TransferPayload {
    private const val FORMAT = "passkey-vault-move"
    private const val VERSION = 1
    private val P256_ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    fun encode(passkeys: List<MovingPasskey>): ByteArray {
        val list = JSONArray()
        passkeys.forEach { moving ->
            list.put(
                moving.passkey.toJson()
                    // Never send this phone's wrapped copy or its flags; the receiver makes its own.
                    .apply { remove("wrappedKey"); remove("movable"); remove("backedUp") }
                    .put("publicKey", Base64Url.encode(moving.publicKey))
                    .put("privateKey", Base64Url.encode(moving.privateKey)),
            )
        }
        return JSONObject().put("format", FORMAT).put("version", VERSION).put("passkeys", list)
            .toString().toByteArray(Charsets.UTF_8)
    }

    /** Parses and checks a received document; throws IllegalArgumentException if anything is off. */
    fun decode(bytes: ByteArray): List<MovingPasskey> {
        val root = JSONObject(String(bytes, Charsets.UTF_8))
        require(root.optString("format") == FORMAT) { "Not passkeys from Passkey Vault" }
        require(root.optInt("version") == VERSION) { "Sent by a different version of Passkey Vault; update both phones" }
        val list = root.getJSONArray("passkeys")
        return (0 until list.length()).map { i ->
            val o = list.getJSONObject(i)
            val passkey = Passkey.fromJson(o).copy(movable = false, backedUp = false, wrappedKey = "")
            require(OriginRules.isValidDomain(passkey.rpId)) { "Invalid site in passkey $i" }
            require(Base64Url.decode(passkey.credentialId).size in 16..1023) { "Invalid credential id in passkey $i" }
            MovingPasskey(passkey, Base64Url.decode(o.getString("publicKey")), Base64Url.decode(o.getString("privateKey")))
        }
    }

    /** Parses a received key pair and proves the two halves belong together (and are P-256). */
    fun keyPair(moving: MovingPasskey): Pair<ECPublicKey, PrivateKey> {
        val factory = KeyFactory.getInstance("EC")
        val publicKey = factory.generatePublic(X509EncodedKeySpec(moving.publicKey)) as ECPublicKey
        require(publicKey.params.order == P256_ORDER) { "Not a P-256 key" }
        val privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(moving.privateKey))
        val probe = "passkey-vault-move key check".toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(probe)
            sign()
        }
        val matches = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(probe)
            verify(signature)
        }
        require(matches) { "The private key doesn't match the public key" }
        return publicKey to privateKey
    }
}
