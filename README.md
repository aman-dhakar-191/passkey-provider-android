# passkey-provider-android (Passkey Vault)

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
| Self-update from GitHub Releases (GitHub build only) | `app/src/github/.../update/` |

**Desktop sign-in via QR code:** the QR code starts the FIDO *hybrid* protocol, which checks that
the phone is physically near the computer over Bluetooth and then opens an encrypted tunnel. On
Android that protocol is run by Google Play services. Once connected, it asks Credential Manager,
which offers this app's passkeys. So the app needs no extra code for QR sign-in, but it does need
**Google Play services and Bluetooth**.

**Using the app:**
- Passkeys are grouped by site. Search appears once you have more than three passkeys, and you can
  give a passkey a name (✏️). The name only shows on this phone, including in Android's sign-in sheet.
- On **Android 15 and newer** with a fingerprint (or other strong biometric) enrolled, the check
  happens inside Android's passkey sheet, so choosing a passkey and verifying is one step. The activity
  log then says "User verified in Android's passkey sheet". On Android 14, the app shows its own prompt
  after you choose. Either way it's strong biometrics or the device PIN/pattern/password; those are
  what unlock the keys.

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
./gradlew testGithubDebugUnitTest assembleGithubDebug   # debug APK in app/build/outputs/apk/github/debug/
```

Debug builds use the package `io.github.amandhakar.passkey.debug` and have self-update turned off.

## Releasing

1. **One-time setup: create the signing key and add it to the repo secrets.** Every release must be
   signed with the same key, or Android refuses to install updates. Keep a backup of the key.

   ```bash
   keytool -genkeypair -v -keystore release.jks -alias passkey -keyalg RSA -keysize 4096 -validity 36500
   base64 -w0 release.jks   # copy the output
   ```

   On Windows PowerShell, which has no `base64` command, use this to copy it to the clipboard:

   ```powershell
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD\release.jks")) | Set-Clipboard
   ```

   Under *Settings → Secrets and variables → Actions*, add these secrets:
   `KEYSTORE_BASE64` (the base64 output), `KEYSTORE_PASSWORD`, `KEY_ALIAS` (`passkey`) and `KEY_PASSWORD`.

2. **For each release:** go to **Actions → Release → Run workflow** and pick the kind of change:
   - `patch`: fixes (1.0.2 → 1.0.3)
   - `minor`: new features (1.0.2 → 1.1.0)
   - `major`: big changes (1.0.2 → 2.0.0)

   The workflow works out the next number from the latest release. You can also type an exact
   version, or push a tag (`git tag v1.0.0 && git push origin v1.0.0`). It runs the tests, builds and
   signs the APK, and publishes a GitHub release with the APK and its SHA-256.

The version must be `MAJOR.MINOR.PATCH`, with each part between 0 and 99. The `versionCode` is
derived from it, so it always goes up.

## Release channels

The same code (one branch) builds two variants, as Gradle product flavors:

| Channel | Variant | Updates | How to release |
|---|---|---|---|
| **GitHub** (sideload) | `github` | the app updates itself from GitHub Releases | *Actions → Release* |
| **Google Play / Indus Appstore** | `store` | by the store; no self-updater, no install-packages permission | release on GitHub first, then *Actions → Store release* (builds that version as a signed `.aab` + `.apk`) |

The store variant doesn't just switch the updater off. The updater, its permissions and WorkManager
live in `app/src/github/`, which the store build never compiles. The store build gets only a stub
(`app/src/store/`). `scripts/check-store-build.sh` runs in CI and in *Store release*. It fails if the
store APK/AAB contains the install-packages or notification permission, the updater classes, the
package installer, WorkManager or the GitHub API. To prove the check itself works, it also checks
that the same things *are* found in the GitHub build.

Store listing text, Data-safety answers and signing notes are in
[docs/store-listing.md](docs/store-listing.md). The privacy policy is [PRIVACY.md](PRIVACY.md).

**Website:** https://aman-dhakar-191.github.io/passkey-provider-android/, with the privacy policy at
[`/privacy/`](https://aman-dhakar-191.github.io/passkey-provider-android/privacy/). It's built from `site/`,
`PRIVACY.md` and the store screenshots by `scripts/build_site.py`, and deployed by the *Website*
workflow on every change to `main`. Its "last changed" dates come from git, so edit `PRIVACY.md` and the
date updates itself.

## Installing and updating

1. Download the APK from the latest [release](../../releases/latest) and install it.
2. Tap **Passkey settings** in the app. It opens *Passwords, passkeys & accounts*; the name differs
   between phone makers. There, turn the app on and pick **Passkey Vault** as the preferred
   service.
3. Updates: the app checks GitHub once a day and shows a notification when a new version is out.
   You can also check from the app's main screen. The first time, Android asks you to let the app
   install updates.
   - The download is checked against the SHA-256 that GitHub reports.
   - Android also refuses any APK that isn't signed with the same key as the installed app.

## Troubleshooting

**The app is not offered, or only "USB security key" / "Use another device" appear.**
- In Android settings, Passkey Vault must be switched on and chosen as the preferred service.
- **Chrome** must be up to date and set to use other services: *Chrome → Settings → Autofill
  services → Autofill using another service*, then close and reopen Chrome. An old or disabled
  Chrome keeps sending every passkey request to Google Password Manager. Apps that open their login
  page in Chrome, such as the Salesforce app, are affected too. Edge works without extra settings.

**Something fails and the browser only says "Something went wrong".** Browsers and Windows hide the
provider's error. Open the app and look at the **Passkey activity log** card. It records each
request, including which app asked and for which site, and why it failed. Tap **Copy details** to
share it. If no line appears for your attempt, Android never asked the app; check the settings
above.

**The app crashes.** It shows a crash report screen with **Copy** and **Share** buttons.

## Testing

- **CI** (every PR): unit tests, lint, debug and release builds of both channels, and the
  store-build check above.
- **Release builds are shrunk with R8** (no renaming: the source is public, and readable stack traces
  help). Because R8 once removed code that is only created by reflection, the emulator test runs on a
  debug build *and* on a `minified` build with the release R8 settings.
- **Security** (every PR, pushes to main, weekly; `.github/workflows/security.yml`):
  - CodeQL static analysis with the security-extended queries; results are under *Security → Code
    scanning*.
  - The Gradle dependency graph is submitted to GitHub, so Dependabot alerts cover the app's real
    dependencies. PRs fail if they add a dependency with a known moderate-or-worse vulnerability.
  - gitleaks scans the whole history for committed secrets.
  - zizmor audits the workflows.

  The workflows are hardened: every action is pinned to a commit SHA (Dependabot updates the pins),
  tokens are read-only unless a job needs more, and signed release builds don't use the Gradle cache.
- **Emulator test** (every PR, `.github/workflows/emulator.yml`): boots Android 14 and 16
  emulators, once for the debug build and once for the R8-minified one, and makes the app the passkey provider. It then asks Credential Manager to create a
  passkey and sign in with it, and checks the signature. `scripts/emulator_selftest.py` taps through
  the system sheets and PIN prompts. Screenshots, the app's log and logcat are uploaded as artifacts.
  The self-test runs only in debug builds. It uses the reserved RP ID
  `selftest.passkey-provider.invalid`, which only the app itself may use, and only in debug builds.

## Known limitations

- Only ES256 (P-256) keys. Nearly every site accepts these.
- Attestation is always `none`. Sites that require enterprise attestation will reject the passkey.
- The browser rpId check allows the origin's host or any parent domain. It doesn't consult the
  public-suffix list, but browsers already block RP IDs that are public suffixes.
