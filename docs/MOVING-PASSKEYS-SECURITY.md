# Moving passkeys: threat model

This covers Passkey Vault's GitHub build: movable passkeys and *⋮ → Move passkeys*. The code is in
`app/src/github/.../transfer/`, `crypto/PasskeyKeys.kt` and the `securechannel` module. Phone-only passkeys
(the default, and every passkey in the store build) are not affected: their keys can't leave the phone.

No encryption is "uncrackable". The aim here is that taking a passkey needs one of these:
- breaking AES-256, X25519 or SHA-256, which nobody can do with known methods;
- getting the QR code's one-time secret;
- the phone's screen-lock PIN/pattern/password or fingerprint;
- full control of a phone's operating system.

Each threat below says which of these it comes down to, and what the code does about it.

## What protects what

| Asset | Where | Protection |
|---|---|---|
| Signing key of a movable passkey | Android Keystore (imported) | The same as phone-only passkeys: one fingerprint/screen-lock prompt per signature, and the key can't be read out of the Keystore |
| Copy of the private key, for moving | `passkeys.json` (app-private), encrypted | AES-256-GCM with a fresh key per passkey. That key is wrapped by RSA-3072-OAEP, whose private half is the Keystore "vault" key. The vault decrypts only within 30 s of a **fingerprint** check (never the PIN), and the Keystore destroys it if fingerprints are added or removed. The credential ID is bound as associated data |
| Passkeys in transit | Wi-Fi, between the two phones | The secure channel: X25519 ECDH with a commitment, keys from HKDF-SHA256 that mix in the QR code's 32-byte secret, AES-256-GCM records with counter nonces, and a SHA-256 of the whole payload |
| QR secret | Only on the new phone's screen | Shown once, never sent over the network, blocked from screenshots, screen recording and Recents (`FLAG_SECURE`), new for every session |

## Threats

| # | Who / what | Can they get passkeys? | Why / what the code does | Tested by |
|---|---|---|---|---|
| 1 | Someone recording the Wi-Fi traffic | No | Everything after the first three handshake messages is AES-256-GCM. The keys come from ECDH **and** the QR secret, which never crosses the network. A recording is useless even to a future quantum computer that breaks X25519, because the 256-bit QR secret is still missing | `AttackTest`: no plaintext or QR secret on the wire |
| 2 | Someone on the Wi-Fi acting as a man in the middle | No | Without the QR secret their keys differ, so the key confirmation fails before any passkey is sent. The old phone only sends after that confirmation | `ChannelTest` / self-test: wrong QR secret refused on both sides |
| 3 | Someone on the Wi-Fi replaying a recorded transfer | No | Each session uses fresh keys and nonces on both sides, so old messages don't fit | `AttackTest`: replay refused |
| 4 | Someone on the Wi-Fi connecting to the new phone first, or holding a connection open, to block the transfer | They can delay it, not take anything | The receiver drops connections that fail the handshake or stay silent for 15 s and keeps listening, up to 20 connections. After that it stops and you start again with a new QR code and port | `AttackTest`: stranger dropped; silent connection timed out; gives up after too many |
| 5 | Someone who photographs the new phone's QR code and connects first | They could *offer* passkeys to your new phone, not take any | The new phone lists the accounts it received and adds nothing until you tap **Add**. If you didn't expect them, tap **Don't add** | Two-phone test |
| 6 | Someone who gets you to scan **their** QR code with your old phone ("scan this to fix your account") | **Yes**: the QR code decides where the passkeys go | The old phone warns before scanning that whoever shows the code gets the passkeys, and asks for your fingerprint before sending. **Only scan a QR code on your own phone, in front of you.** | n/a (social engineering) |
| 7 | A thief with your old phone who knows your PIN, or watched you type it | No | Sending, and turning **Can be moved** on, need a fingerprint, and the PIN isn't offered. This is enforced by the Keystore, not just the screen: the vault key accepts only a strong biometric. Adding their own fingerprint (which only needs the PIN) makes the Keystore destroy the vault, so existing copies can no longer be opened at all. Without a fingerprint enrolled, passkeys can't be made movable, sent or received | Two-phone test |
| 8 | A malicious app on either phone | No | It can't read the app's files or Keystore keys. The transfer screen isn't exported and the QR code is blocked from screen capture. It could read the screen if you granted it accessibility access, which no passkey app can defend against | Manifest check in CI (`scripts/check-manifest.py`) |
| 9 | A rooted or compromised phone | Possibly | Full OS control can read memory while a key is being moved (keys are wiped after use, best effort) and can use the Keystore when you unlock it. That's true of every app on such a phone | n/a |
| 10 | Someone copying `passkeys.json` (backup, file access) | No | The app turns backups off (`allowBackup=false`, data extraction excluded). Even with the file, each copy is encrypted under a Keystore key that never leaves the phone and needs your fingerprint | `MovePasskeysTest`: wrong credential or tampered blob refused |
| 11 | Someone pushing junk to the new phone | No | It needs the QR secret, then the receiver accepts one item of at most 4 MB and checks the format, every site, and that each private key matches its public key (P-256) | `AttackTest`: extra items refused; `MovePasskeysTest`: mismatched keys, other formats and bad sites refused |
| 12 | Someone flipping the setting so future passkeys become movable without you noticing | No | Turning **Can be moved** on needs your fingerprint (not the PIN) | Two-phone test |

## What "can be moved" costs, compared with phone-only

- **The private key exists outside the secure hardware** for a moment when it's created, sent or received. Sign-in itself still happens inside the Keystore.
- **Copies can exist on more than one phone.** Delete the old phone's copy once the new one works. Sites see these passkeys as "backup eligible", and "backed up" once moved.
- **Threat 6 only exists for movable passkeys.** Threat 7 is closed by the fingerprint rule, at a price:
  adding or removing a fingerprint stops passkeys made before that change from being moved. They still
  sign in on that phone, and passkeys made afterwards can be moved.
- **Copies made by the first version** (before the fingerprint rule) were locked by a key that also accepted
  the PIN. The app re-locks them under the fingerprint-only key at the first chance: quietly when you open
  the app right after unlocking the phone, or when you send them. Until then threat 7 still applies to them.

## Open decisions

- **Threat 7:** decided. Fingerprint only; no fingerprint means no moving.

- **Encrypted backup file:** planned for later. It needs a strong passphrase and a slow key-derivation function (for example Argon2id), because a backup file can be attacked offline, unlike the transfer.
