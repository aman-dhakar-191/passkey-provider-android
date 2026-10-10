# Crypto Lab (experimental)

A separate test app for trying ways to encrypt data and send it to another phone over a secure channel.
It is not part of Passkey Vault or Passkey Demo, and nothing in `app/` or `demo/` uses it. Once an approach is
final and working, it can be moved into the real apps.

## Trying it

1. Get the APK from the **Crypto Lab** workflow (Actions → Crypto Lab → artifact `cryptolab-debug-apk`) and install it on two phones (Android 14+).
2. **Run self-test** on one phone. It runs every approach over loopback, plus the attacks below.
3. Put both phones on the same Wi-Fi network, or connect one to the other's hotspot.
   - Phone A: **Wait for senders**. It lists its addresses, Wi-Fi and hotspot first, and keeps listening until **Stop**.
   - Phone B: enter phone A's Wi-Fi address and tap **Connect**.
4. Both phones show a 6-digit code. Tap **Codes match** only if the two codes are the same.
5. Phone B can now send any number of messages, files, or 1 MB / 10 MB tests over that one channel. **Disconnect** ends the session; phone A keeps waiting for the next sender.

## How the channel works

| Step | What happens |
|---|---|
| Key exchange | Ephemeral ECDH (X25519 or P-256), new keys for every connection (forward secrecy) |
| Commitment | The sender commits to its key before it sees the receiver's, so a man in the middle can't search for keys that make the codes match |
| Key derivation | HKDF-SHA256 over the shared secret, salted with a hash of the whole handshake: one key per direction, plus the 6-digit code |
| Authentication | People compare the code, the same idea as Bluetooth numeric comparison. Without this check, nothing stops a man in the middle |
| Records | AEAD (AES-256-GCM or ChaCha20-Poly1305). A counter is both the nonce and part of the associated data, so changed, replayed, dropped or reordered records are refused |
| Transfer | START (name, size), 32 KiB chunks, END (SHA-256); the receiver replies with its own hash |

The protocol is in `core/SecureChannel.kt`; the comments explain each choice.

## Approaches to compare

| Area | Now | Ideas to try next |
|---|---|---|
| Key exchange | X25519; P-256 (software); P-256 inside the Android Keystore | ML-KEM hybrid (post-quantum); a long-term identity key so phones that have paired once skip the code |
| Encryption | AES-256-GCM, ChaCha20-Poly1305 | |
| Authentication | 6-digit code compared by people | QR code with the key's hash (no typing, no comparing) |
| Transport | TCP on the local network (`transport/TcpTransport.kt`) | Bluetooth RFCOMM, Wi-Fi Direct, Nearby Connections, a relay server for phones that aren't nearby |

To add an approach:
- **Key exchange:** implement `KeyExchange`.
- **Encryption:** implement `Aead`.
- **Register it:** add a `CipherSuite` to `Suites` (or to `LabSuites`, if it needs Android).
- **Transport:** anything that provides a `Connection` (an input and output stream) works with the channel unchanged.

Use vetted primitives only, never home-made ciphers. The lab compares how proven building blocks are put together.

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
- size limits

## Known limits

- **Passkeys can't be moved with this.** Passkey Vault's private keys are created non-exportable in the Keystore. Moving passkeys between phones would need a different design, for example syncable keys or creating new passkeys on the new phone.
- **The receiving phone listens on port 47800.** Anyone on the network can connect to it, but a transfer only goes ahead after both people confirm the code.
- **A connected sender that stays idle for 5 minutes is dropped** by the receiver's read timeout; connect again.
- **Received files are saved to the app's cache folder** (`cache/received/`). Received text up to 2 KB is also shown in the log.
