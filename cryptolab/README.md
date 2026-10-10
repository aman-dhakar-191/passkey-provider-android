# Crypto Lab (experimental)

A separate test app for trying ways to encrypt data and send it to another phone over a secure channel.
It is not part of Passkey Vault or Passkey Demo, and nothing in `app/` or `demo/` uses it. Once an approach is
final and working, it can be moved into the real apps.

## Trying it

1. Install the app on two phones (Android 14+):
   - **Release:** open the [releases page](https://github.com/aman-dhakar-191/passkey-provider-android/releases), pick the newest **Crypto Lab** release (a pre-release, on purpose) and download `crypto-lab-X.Y.Z.apk`. To update, install a newer one over it.
   - **Latest build:** the `cryptolab-debug-apk` artifact of the **Crypto Lab** workflow (Actions → Crypto Lab). A debug build can't be installed over a release, or the other way round; uninstall first.
2. **Run self-test** on one phone. It runs every approach over loopback, plus the attacks below.
3. Pick the same **Transport** on both phones:
   - **Wi-Fi or hotspot:** both phones on the same Wi-Fi, or one connected to the other's hotspot.
   - **Bluetooth:** Bluetooth on for both. The app asks for the Bluetooth permissions the first time. The phones don't need to be paired.
4. Phone A: **Wait for senders**. It shows a QR code and keeps listening until **Stop**. Over Bluetooth it also asks to become discoverable for 5 minutes, so unpaired phones can find it.
5. Phone B: **Scan QR code** and point it at phone A's screen. It connects with no code to compare.
   - **Without the QR code:** Wi-Fi: type phone A's address and tap **Connect**. Bluetooth: **Find phones** and tap phone A. Then both phones show a 6-digit code; tap **Codes match** only if the two are the same.
6. Phone B can now send any number of messages, files, or 1 MB / 10 MB tests over that one channel. **Disconnect** ends the session; phone A keeps waiting for the next sender.

## How the channel works

| Step | What happens |
|---|---|
| Key exchange | Ephemeral ECDH (X25519 or P-256), new keys for every connection (forward secrecy) |
| Commitment | The sender commits to its key before it sees the receiver's, so a man in the middle can't search for keys that make the codes match |
| Key derivation | HKDF-SHA256 over the shared secret, salted with a hash of the whole handshake: one key per direction, plus the 6-digit code |
| Authentication (QR) | The receiver's QR code holds its address and a one-time 32-byte secret. Both phones mix the secret into the key derivation, so anyone who never saw the QR code gets different keys, and the automatic key confirmation fails |
| Authentication (code) | Without the QR code, people compare the 6-digit code, the same idea as Bluetooth numeric comparison. Without one of these checks, nothing stops a man in the middle |
| Records | AEAD (AES-256-GCM or ChaCha20-Poly1305). A counter is both the nonce and part of the associated data, so changed, replayed, dropped or reordered records are refused |
| Transfer | START (name, size), 32 KiB chunks, END (SHA-256); the receiver replies with its own hash |

The protocol is in `core/SecureChannel.kt`; the comments explain each choice.

## Approaches to compare

| Area | Now | Ideas to try next |
|---|---|---|
| Key exchange | X25519; P-256 (software); P-256 inside the Android Keystore | ML-KEM hybrid (post-quantum); a long-term identity key so phones that have paired once skip the code |
| Encryption | AES-256-GCM, ChaCha20-Poly1305 | |
| Authentication | QR code with a one-time secret; 6-digit code compared by people | NFC tap to share the secret |
| Transport | TCP on the local network (`transport/TcpTransport.kt`); Bluetooth Classic RFCOMM (`android/BluetoothTransport.kt`) | Wi-Fi Direct, Nearby Connections, BLE, a relay server for phones that aren't nearby |

To add an approach:
- **Key exchange:** implement `KeyExchange`.
- **Encryption:** implement `Aead`.
- **Register it:** add a `CipherSuite` to `Suites` (or to `LabSuites`, if it needs Android).
- **Transport:** anything that provides a `Connection` (an input and output stream) and a `Listener` works with the channel unchanged.

Use vetted primitives only, never home-made ciphers. The lab compares how proven building blocks are put together.

## Releasing

*Actions → Crypto Lab release → Run workflow*, then pick patch, minor or major (the first release is 0.1.0). It
runs the tests, builds the APK signed with the same key as Passkey Vault, and publishes it with its SHA-256 as
a **pre-release** tagged `cryptolab-vX.Y.Z`.

## Tests

`core/` and `transport/` don't import anything from Android, so the unit tests run on a plain JVM:

```bash
./gradlew :cryptolab:testDebugUnitTest
```

They check:
- HKDF against the RFC 5869 test vector
- every suite end to end over loopback TCP
- that tampered and replayed records are refused
- that a changed key reveal fails the commitment check
- that a man in the middle produces different codes on the two phones
- that a wrong QR secret is refused, and that QR invites encode and parse correctly
- size limits

## Known limits

- **Passkeys can't be moved with this.** Passkey Vault's private keys are created non-exportable in the Keystore. Moving passkeys between phones would need a different design, for example syncable keys or creating new passkeys on the new phone.
- **The receiving phone listens on port 47800, or on Bluetooth RFCOMM.** Anyone nearby can connect, but a transfer only goes ahead with the QR secret or after both people confirm the code.
- **The QR secret lasts for one listening session.** Anyone who sees or photographs the QR code while it's on screen can connect. Stop and start again for a new secret.
- **A sender that didn't scan the QR code** still reaches a receiver showing one, but then both people must compare codes. If you scanned the QR code and the receiver still asks you to compare codes, someone else connected: tap **They differ**.
- **Bluetooth is slower than Wi-Fi.** Expect about 0.1–0.3 MB/s on classic Bluetooth, against several MB/s on Wi-Fi (a rough estimate; measure it with the 1 MB test).
- **A connected sender that stays idle for 5 minutes is dropped** by the receiver's read timeout; connect again.
- **Received files are saved to the app's cache folder** (`cache/received/`). Received text up to 2 KB is also shown in the log.
