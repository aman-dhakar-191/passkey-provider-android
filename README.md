# passkey-provider-android

An Android passkey provider (password-manager-style "credential provider") that stores passkeys on
your phone and uses them to sign in to:

- **Apps and browsers on the phone:** it plugs into Android's Credential Manager, so Chrome and
  apps that use passkeys list it in the system sign-in sheet.
- **Desktop browsers:** on the computer choose *Use a phone or tablet* and scan the QR code, either
  with the phone's camera or with the app's **Scan QR code** button.

It can also **create** new passkeys the same way, both on the phone and from a desktop via QR code.

Requires **Android 14 (API 34) or newer**, with a screen lock set up.

## How it works

| Piece | File |
|---|---|
| Credential Manager entry point (lists passkeys, offers "create") | `provider/PasskeyProviderService.kt` |
| Create / sign-in activities (verify the caller, then prompt for biometrics or screen lock) | `provider/CreatePasskeyActivity.kt`, `provider/GetPasskeyActivity.kt` |
| Anti-phishing: browser origin allowlist and Digital Asset Links check for apps | `provider/CallerVerifier.kt` |
| WebAuthn authenticator (authenticator data, "none" attestation, ES256 signatures) | `provider/Authenticator.kt`, `webauthn/` |
| Private keys (Android Keystore / StrongBox; they never leave the device) | `crypto/PasskeyKeys.kt` |
| Self-update from GitHub Releases | `update/` |

**Desktop sign-in via QR code:** the QR code starts the FIDO *hybrid* protocol, which checks that
the phone is physically near the computer over Bluetooth and then opens an encrypted tunnel. On
Android that protocol is run by Google Play services. Once connected, it asks Credential Manager,
which offers this app's passkeys. So the app needs no extra code for QR sign-in, but it does need
**Google Play services and Bluetooth**.

**Security model:**
- The WebAuthn operation starts only after the calling app has been verified:
  - A browser must be on Google's privileged-browser list. The list is bundled at build time and
    refreshed daily.
  - A native app must be listed in the site's `/.well-known/assetlinks.json` with the
    `get_login_creds` relation.
- Every create and sign-in needs biometrics or the device PIN/pattern/password. The Keystore
  enforces this: a key only works for 30 seconds after the user authenticates.
- Keys are **not backed up or synced**. If you lose the phone, you lose its passkeys, so keep
  another sign-in method on your important accounts.

## Building

```bash
./gradlew testDebugUnitTest assembleDebug     # debug APK in app/build/outputs/apk/debug/
```

Debug builds use the package `io.github.amandhakar.passkey.debug` and have self-update turned off.

## Releasing

1. **One-time setup: create the signing key and add it to the repo secrets.** Every release must be
   signed with the same key, or Android refuses to install updates. Keep a backup of the key.

   ```bash
   keytool -genkeypair -v -keystore release.jks -alias passkey -keyalg RSA -keysize 4096 -validity 36500
   base64 -w0 release.jks   # copy the output
   ```

   Under *Settings → Secrets and variables → Actions*, add these secrets:
   `KEYSTORE_BASE64` (the base64 output), `KEYSTORE_PASSWORD`, `KEY_ALIAS` (`passkey`) and `KEY_PASSWORD`.

2. **For each release, push a version tag:**

   ```bash
   git tag v1.0.0 && git push origin v1.0.0
   ```

   You can also run the **Release** workflow manually and enter a version. The workflow runs the
   tests, builds and signs the APK, and publishes a GitHub release with the APK and its SHA-256.

The version must be `MAJOR.MINOR.PATCH`, with each part between 0 and 99. The `versionCode` is
derived from it, so it always goes up.

## Installing and updating

1. Download the APK from the latest [release](../../releases/latest) and install it.
2. Turn it on under *Settings → Passwords, passkeys & accounts* (the app's **Open settings** button
   goes there).
3. Updates: the app checks GitHub once a day and shows a notification when a new version is out.
   You can also check from the app's main screen. The first time, Android asks you to let the app
   install updates.
   - The download is checked against the SHA-256 that GitHub reports.
   - Android also refuses any APK that isn't signed with the same key as the installed app.

## Known limitations

- Only ES256 (P-256) keys. Nearly every site accepts these.
- Attestation is always `none`. Sites that require enterprise attestation will reject the passkey.
- The browser rpId check allows the origin's host or any parent domain. It doesn't consult the
  public-suffix list, but browsers already block RP IDs that are public suffixes.
