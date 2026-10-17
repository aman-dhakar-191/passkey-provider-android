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

## Encrypted backup file

*⋮ → Move passkeys → Encrypted backup file* saves the movable passkeys into one file you can keep on Google
Drive, another cloud app, or the phone. The code is `transfer/BackupFile.kt`; the file is chosen with Android's
own file picker, so the app needs no storage permission, no Google account and no network access for it.

**"Only this app can open it" can't be enforced, and the app doesn't try.** The source is public, so anyone can
write a program that reads the format. What the app guarantees is that the file **can't be opened without the
recovery key**. The file holds no key, and the key is not derived from anything about the phone or the app.

How it works:
- **Recovery key:** 32 random bytes (256 bits), made fresh for every backup and shown once as 56 letters and
  digits (no 0/1/I/O) with a 3-byte check that catches typos. Nothing is stored on the phone or in the file.
  It is random rather than a password you pick, so there is nothing to guess and no password-hashing step is
  needed. The cost: **lose the key and the backup can never be opened by anyone.**
- **File:** `PVBK` | version | 16-byte salt | 12-byte nonce | AES-256-GCM ciphertext. The AES key is
  HKDF-SHA256 of the recovery key and the salt, and the header is authenticated, so a changed file is refused.
- **Contents:** the same document as a phone-to-phone move (passkeys with their private keys), and the same
  receiver checks apply when restoring: format, every site, each private key matching its public key, and
  nothing is added until you tap **Add**.
- **Making a backup** needs a fingerprint (never the PIN), like sending. The file is written only after you
  confirm you saved the recovery key, so a backup can't be left behind with a key nobody saw.

| # | Who / what | Can they get passkeys? | Why / what the code does |
|---|---|---|---|
| 13 | Someone who gets the backup file (a hacked cloud account, the cloud provider, a lost USB stick) | No | Without the recovery key they would have to break AES-256-GCM. `BackupFileTest`: wrong key refused, any changed byte refused, no plaintext or key in the file |
| 14 | Someone who gets the file **and** the recovery key | **Yes** | They can restore it on their own phone with their own fingerprint. The restore isn't tied to your phone or your fingerprint, which is what makes a backup useful when your phone is lost. **Keep the key and the file in different places** (the key in a password manager or on paper) |
| 15 | A thief with your phone and PIN making a backup | No | Making a backup needs a fingerprint, enforced by the vault key in the Keystore (threat 7) |
| 16 | You lose the recovery key | Nobody can open the backup | By design. Make a new backup (it gets a new key) while you still have the phone |
| 17 | Someone who sees or copies the key from your screen or clipboard | Possibly | The key screen blocks screenshots and recording (`FLAG_SECURE`), and **Copy** marks the clipboard entry sensitive, but any app you paste into, or the clipboard itself, is outside this app's control |
| 18 | Someone tampering with a backup, or giving you a crafted one | No | The format is authenticated, restoring checks every field like a received transfer, and nothing is added without your tap. A crafted file also needs the recovery key to open at all |

Restoring needs a fingerprint on the phone, because the restored passkeys are locked under the same
fingerprint-only vault as any other movable passkey.

## Open decisions

- **Threat 7:** decided. Fingerprint only; no fingerprint means no moving.
- **Backup file:** decided. A random recovery key instead of a password. A password option could be added
  later, but it would need a slow key-derivation function (Argon2id or scrypt, neither built into Android) and a
  strength check, because a backup file can be attacked offline, unlike the transfer.
