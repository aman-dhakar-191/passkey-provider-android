package io.github.amandhakar.cryptolab.core

import java.io.Closeable
import java.net.ProtocolException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Handshake (protocol v1) between the phone that connects (initiator, "sender") and the one that listens
 * (responder, "receiver"):
 *
 *  1. I -> R  COMMIT  suite id, H("commit" || pkI || nI)
 *  2. R -> I  HELLO   status, suite id, pkR, nR
 *  3. I -> R  REVEAL  pkI, nI           (R checks it matches the commitment)
 *
 * Both derive, from ECDH(pkI, pkR) and a hash of the three messages:
 *  - one AEAD key per direction, and
 *  - a 6-digit code (SAS) that both people compare on their screens.
 *
 * Why the commitment: a man in the middle runs a separate handshake with each phone. Without it, after
 * seeing both public keys it could try millions of its own keys until the two codes match. With it, the
 * initiator's key is fixed before the responder's is seen, so the attacker gets one guess in a million.
 * (The same idea as Bluetooth numeric comparison and ZRTP.)
 *
 * Until both people confirm that the codes match, nothing but the confirmation is sent.
 */
object Handshake {
    const val VERSION = 1
    private val MAGIC = "CLAB".toByteArray()
    private const val NONCE_SIZE = 32
    private const val STATUS_OK = 0
    private const val STATUS_UNSUPPORTED = 1

    fun initiate(connection: Connection, suite: CipherSuite, random: SecureRandom = SecureRandom()): PendingChannel {
        val framer = Framer(connection)
        val own = suite.kex.generate()
        try {
            val pk = suite.kex.encode(own.public)
            val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
            val m1 = WireWriter().raw(MAGIC).u8(VERSION).string(suite.id).bytes(commitment(pk, nonce)).build()
            framer.write(m1)

            val m2 = framer.read()
            val r = WireReader(m2)
            readHeader(r)
            val status = r.u8()
            val suiteId = r.string()
            if (status == STATUS_UNSUPPORTED) throw ProtocolException("The other phone does not support ${suite.label}")
            if (status != STATUS_OK || suiteId != suite.id) throw ProtocolException("Unexpected reply to the handshake")
            val peerPk = r.bytes()
            val peerNonce = r.bytes()
            r.end()
            if (peerNonce.size != NONCE_SIZE) throw ProtocolException("Bad nonce")

            val m3 = WireWriter().bytes(pk).bytes(nonce).build()
            framer.write(m3)
            return derive(Role.INITIATOR, framer, connection, suite, own, peerPk, m1, m2, m3)
        } finally {
            suite.kex.dispose(own)
        }
    }

    /** [suiteFor] returns this phone's implementation of the suite id the initiator asked for, or null. */
    fun respond(
        connection: Connection,
        suiteFor: (String) -> CipherSuite?,
        random: SecureRandom = SecureRandom(),
    ): PendingChannel {
        val framer = Framer(connection)
        val m1 = framer.read()
        val r1 = WireReader(m1)
        readHeader(r1)
        val suiteId = r1.string()
        val commit = r1.bytes()
        r1.end()
        val suite = suiteFor(suiteId)
        if (suite == null) {
            framer.write(WireWriter().raw(MAGIC).u8(VERSION).u8(STATUS_UNSUPPORTED).string(suiteId).build())
            throw ProtocolException("The other phone asked for an unsupported suite: $suiteId")
        }

        val own = suite.kex.generate()
        try {
            val pk = suite.kex.encode(own.public)
            val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
            val m2 = WireWriter().raw(MAGIC).u8(VERSION).u8(STATUS_OK).string(suite.id).bytes(pk).bytes(nonce).build()
            framer.write(m2)

            val m3 = framer.read()
            val r3 = WireReader(m3)
            val peerPk = r3.bytes()
            val peerNonce = r3.bytes()
            r3.end()
            if (!MessageDigest.isEqual(commit, commitment(peerPk, peerNonce))) {
                throw SecurityException("The other phone's key does not match its commitment")
            }
            return derive(Role.RESPONDER, framer, connection, suite, own, peerPk, m1, m2, m3)
        } finally {
            suite.kex.dispose(own)
        }
    }

    private fun readHeader(r: WireReader) {
        if (!r.raw(MAGIC.size).contentEquals(MAGIC)) throw ProtocolException("Not a Crypto Lab peer")
        val version = r.u8()
        if (version != VERSION) throw ProtocolException("Protocol version $version not supported (this phone speaks $VERSION)")
    }

    private fun commitment(pk: ByteArray, nonce: ByteArray) =
        sha256("cryptolab v1 commit".toByteArray(), WireWriter().bytes(pk).bytes(nonce).build())

    private fun derive(
        role: Role,
        framer: Framer,
        connection: Connection,
        suite: CipherSuite,
        own: java.security.KeyPair,
        peerPkBytes: ByteArray,
        m1: ByteArray,
        m2: ByteArray,
        m3: ByteArray,
    ): PendingChannel {
        val shared = suite.kex.agree(own, suite.kex.decode(peerPkBytes))
        val transcript = sha256(WireWriter().raw(lengthPrefixed(m1)).raw(lengthPrefixed(m2)).raw(lengthPrefixed(m3)).build())
        val prk = Hkdf.extract(transcript, shared)
        val i2r = Hkdf.expand(prk, "cryptolab v1 key i2r".toByteArray(), suite.aead.keySize)
        val r2i = Hkdf.expand(prk, "cryptolab v1 key r2i".toByteArray(), suite.aead.keySize)
        val sasBytes = Hkdf.expand(prk, "cryptolab v1 sas".toByteArray(), 4)
        shared.fill(0)
        prk.fill(0)
        val sas = (ByteBuffer.wrap(sasBytes).int.toLong() and 0xFFFFFFFFL) % 1_000_000
        val channel = SecureChannel(
            framer = framer,
            connection = connection,
            suite = suite,
            sendKey = if (role == Role.INITIATOR) i2r else r2i,
            receiveKey = if (role == Role.INITIATOR) r2i else i2r,
            sendDirection = if (role == Role.INITIATOR) 1 else 2,
        )
        return PendingChannel(
            sas = "%03d %03d".format(sas / 1000, sas % 1000),
            sessionId = transcript.copyOf(8).hex(),
            channel = channel,
        )
    }

    private fun lengthPrefixed(m: ByteArray) = ByteBuffer.allocate(4).putInt(m.size).array() + m

    enum class Role { INITIATOR, RESPONDER }
}

/**
 * A finished key exchange waiting for both people to compare [sas]. Call [confirm] with what this person
 * said; it returns the open channel once the other phone has confirmed too.
 */
class PendingChannel internal constructor(
    val sas: String,
    /** Short id of this handshake, for the log (the same on both phones unless someone is in the middle). */
    val sessionId: String,
    private val channel: SecureChannel,
) : Closeable {
    val suite get() = channel.suite

    fun confirm(codesMatch: Boolean): SecureChannel {
        if (!codesMatch) {
            runCatching { channel.send(RecordType.CLOSE, "codes did not match".toByteArray()) }
            channel.close()
            throw SecurityException("You said the codes did not match; connection closed")
        }
        channel.send(RecordType.CONFIRM, CONFIRM_PAYLOAD)
        val reply = channel.receive()
        when {
            reply.type == RecordType.CONFIRM && reply.payload.contentEquals(CONFIRM_PAYLOAD) -> return channel
            reply.type == RecordType.CLOSE -> {
                channel.close()
                throw SecurityException("The other phone said the codes did not match")
            }
            else -> {
                channel.close()
                throw ProtocolException("Unexpected record ${reply.type} instead of the confirmation")
            }
        }
    }

    override fun close() = channel.close()

    private companion object {
        val CONFIRM_PAYLOAD = "cryptolab v1 confirm".toByteArray()
    }
}

object RecordType {
    const val CONFIRM = 1
    const val START = 2
    const val DATA = 3
    const val END = 4
    const val ACK = 5
    const val CLOSE = 6
}

class Record(val type: Int, val payload: ByteArray)

/**
 * Encrypted records after the handshake. Each direction has its own key and a counter that is the nonce
 * and part of the associated data, so a record that is changed, replayed, dropped or reordered fails to
 * decrypt and the channel stops.
 */
class SecureChannel internal constructor(
    private val framer: Framer,
    private val connection: Connection,
    val suite: CipherSuite,
    private val sendKey: ByteArray,
    private val receiveKey: ByteArray,
    private val sendDirection: Int,
) : Closeable {
    private val receiveDirection = 3 - sendDirection
    private var sendSeq = 0L
    private var receiveSeq = 0L

    val peer: String get() = connection.peer

    @Synchronized
    fun send(type: Int, payload: ByteArray) {
        require(payload.size <= MAX_PAYLOAD) { "Record payload too large" }
        val plaintext = byteArrayOf(type.toByte()) + payload
        framer.write(suite.aead.seal(sendKey, nonce(sendDirection, sendSeq), aad(sendDirection, sendSeq), plaintext))
        sendSeq++
    }

    fun receive(): Record {
        val sealed = framer.read()
        val plaintext = try {
            suite.aead.open(receiveKey, nonce(receiveDirection, receiveSeq), aad(receiveDirection, receiveSeq), sealed)
        } catch (e: Exception) {
            close()
            throw SecurityException("Record #$receiveSeq failed authentication (changed, replayed or out of order)", e)
        }
        receiveSeq++
        if (plaintext.isEmpty()) throw ProtocolException("Empty record")
        return Record(plaintext[0].toInt() and 0xFF, plaintext.copyOfRange(1, plaintext.size))
    }

    override fun close() {
        sendKey.fill(0)
        receiveKey.fill(0)
        runCatching { connection.close() }
    }

    private fun nonce(direction: Int, seq: Long): ByteArray =
        ByteBuffer.allocate(12).put(direction.toByte()).put(ByteArray(3)).putLong(seq).array()

    private fun aad(direction: Int, seq: Long): ByteArray =
        AAD_PREFIX + byteArrayOf(direction.toByte()) + ByteBuffer.allocate(8).putLong(seq).array()

    companion object {
        const val MAX_PAYLOAD = 64 * 1024
        private val AAD_PREFIX = "cryptolab v1 record".toByteArray()
    }
}
