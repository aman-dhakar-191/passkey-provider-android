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

## Backup & recovery

*⋮ → Backup & recovery* (GitHub build) puts the movable passkeys into one encrypted file that can be kept
anywhere (Google Drive, another cloud app, the phone), and splits the file's key between **keepers**, so that
nobody has to remember or store a key, and no single party can open the backup. The code is in
`app/src/github/.../recovery/`.

**"Only this app can open it" can't be enforced, and the app doesn't try.** The source is public, so anyone
can write a program that reads the format. What the design guarantees is that the file can't be opened
without **two keepers' pieces**.

How it works:
- **Backup file** (`BackupFile.kt`): `PVBK` | version | backup id | salt | nonce | AES-256-GCM ciphertext. The
  AES key is HKDF-SHA256 of the 256-bit backup key and the salt; the header is authenticated. Inside: the
  same document as a phone-to-phone move, plus the keeper list (labels and piece numbers, no secrets), so a
  restored phone knows its keepers. Written through Android's file picker: no storage permission, no Google
  account, no network use by the app. Read back after writing, because some storage apps don't truncate.
- **Pieces** (`Shamir.kt`, `RecoveryShare.kt`): the key is the value at x = 0 of a random straight line
  over GF(2^8), byte by byte (Shamir secret sharing, threshold 2). Each keeper gets the value at a different
  x. Any two pieces give the line back, and with it the key; one piece gives no information about the key
  at all, whatever computing power is used (tested exhaustively for one byte in `ShamirTest`).
- **Owner's phone:** keeps the key and one more point (x = 255, never handed out), encrypted under the same
  fingerprint-only Keystore vault as movable passkeys, so it can make a new piece for a new keeper, or update
  the file, after a **fingerprint** (never the PIN). It keeps a **check key** per piece, HKDF of the piece,
  which can't be turned back into the piece.
- **Keepers:**
  - **Google** (`GoogleKeeper.kt`): Block Store in Google Play services. Only stored when Block Store says
    its cloud backup is end-to-end encrypted (needs a screen lock); comes back on a new phone set up from the
    Google backup, after the old screen lock is entered.
  - **Printed card** (`ShareCard.kt`): the piece as a QR code and text, sent straight to Android's print
    dialog; the app never saves the PDF. Works on any phone with a camera; no NFC needed.
  - **A person's phone, or your own spare phone** (`QrLink.kt`): handed over in person with the same
    QR-and-Wi-Fi secure channel as moving passkeys. Their Passkey Vault keeps it encrypted with a Keystore
    key that only works while their phone is unlocked, and gives it back only after their screen lock, by
    scanning a QR code on the restoring phone.
- **Health checks** (`ShareCheck.kt`, `BackupHealth.kt`): so a lost piece is found while the phone still
  works, not after it's gone.
  - Person: the owner sends a challenge through any messaging app; the keeper's Passkey Vault answers with a
    short code, HMAC of the challenge under the piece's check key. The owner's phone checks it. The piece
    never travels; an answer can't be replayed for a later challenge.
  - Card: scan it; the app compares its check key.
  - Google: the app reads this phone's copy and compares it, and stores it again to refresh Google's copy.
    **It can't see the copy in Google's cloud**, so this check is partial.
  - File: read back and compared with the hash saved when it was written.
  - Status is green with three working keepers and a current file, yellow when a check is older than 90
    days, a keeper is unchecked, only two keepers work or the file is out of date, red when fewer than two
    keepers can be counted on or the file is missing. A daily, offline job notifies (at most every 14 days)
    while it isn't green.
- **Restore:** choose the backup file, then get any two pieces: from Google (if the phone was set up from
  the Google backup), by scanning or typing a card, or from a keeper's phone in person. The passkeys go through
  the same checks and **Add** confirmation as a received move. The new phone then takes over the backup and
  its keepers (their pieces still fit), each marked "not checked from this phone yet".

| # | Who / what | Can they get passkeys? | Why / what the code does |
|---|---|---|---|
| 13 | Someone who gets the backup file (a hacked cloud account, the cloud provider) | No | Without the key they'd have to break AES-256-GCM. `BackupFileTest`: no plaintext or key in the file, any changed byte refused |
| 14 | One keeper alone: Google, whoever finds the card, or a trusted person | No | One piece reveals nothing about the key (`ShamirTest`) |
| 15 | **Any two keepers together**, with the file | **Yes** | That's what restoring is. Choose keepers who wouldn't work together against you; don't put the card in Google Photos, Drive or e-mail (that gives Google two pieces; the card says so) |
| 16 | A thief with your phone and PIN | No | Making pieces or updating the file needs the vault, i.e. a fingerprint (threat 7). They also don't get pieces you gave others |
| 17 | Someone who asks a keeper to "give back" a piece | Only that one piece | Giving back needs the keeper's screen lock and scanning a QR code on the asking phone, in person. The app tells keepers to give it back only to the owner, in front of them |
| 18 | Someone who sees a check or an answer (the messaging app) | No | They're random challenges and HMAC codes; they say nothing about the piece and can't be replayed (`RecoveryShareTest`) |
| 19 | A crafted backup file or keeper list | No | The file is authenticated by the key; restored passkeys get every receiver check and need **Add**; the keeper list is size-limited and cut down to valid entries (`BackupSetJsonTest`) |
| 20 | Losing keepers over time | Restore fails if fewer than two remain | Health checks and reminders make it visible early. **Start over** makes a new key (old pieces and old files stop matching new backups; delete old files, since old pieces still open them) |
| 21 | Google's copy isn't really there (backup off, cloud copy lost) | Restore needs two other keepers | The app can only check this phone's copy, and stores Google's piece only when Block Store reports end-to-end encryption. Three keepers mean losing Google's piece alone doesn't stop a restore |

Fingerprint changes destroy the vault (threat 7), and with it this phone's copy of the backup key: existing
keepers can still restore the last backup, but to back up again from that phone, **Start over**.

## Open decisions

- **Threat 7:** decided. Fingerprint only; no fingerprint means no moving.
- **Backup key:** decided. Split between keepers (2 of N), so nobody has to remember or store a key. A
  password option was rejected: people forget passwords, and a backup file can be attacked offline.
