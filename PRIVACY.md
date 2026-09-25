# Privacy policy: Passkey Vault

Passkey Vault is a passkey manager for Android. It stores passkeys **only on your device** and has no
account, server or analytics.

## What the app stores
- **Passkeys.** Each passkey's private key is created inside your phone's Android Keystore (secure
  hardware where available). It never leaves the phone, and nobody can copy it out, including us.
- **Passkey details.** For each passkey the app keeps the website or app it belongs to, the account name
  the site provided, dates of creation and last use, and a name you may give it. This is stored in the
  app's private storage on your phone. It is not backed up or synced.
- **Activity log.** A local log of recent passkey requests (which app asked, for which site, and any
  errors), to help you troubleshoot. It stays on the phone. You can copy it yourself or clear it.

## What the app sends over the internet
The app sends no personal data. It only downloads public files:
- **Google's list of trusted browsers**
  (`https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json`), about once a day, to check that
  a browser asking for a passkey is genuine.
- **A website's `/.well-known/assetlinks.json`**, when an app (not a browser) asks for a passkey, to
  check that the website allows that app to use its passkeys.
- **GitHub version only:** the latest release information and, if you choose to update, the new APK
  from `github.com/aman-dhakar-191/passkey-provider-android`. Versions installed from an app store
  don't do this; the store handles updates.

Like any internet request, these reveal your IP address to the server that answers (Google, the
website, or GitHub).

## QR-code scanning
The **Scan QR code** button uses Google's code scanner, which is part of Google Play services and runs
on your device. Google's handling of data by Google Play services is covered by Google's own privacy
policy.

## What we don't do
No accounts, no tracking, no ads, no analytics, no crash reporting to any server, no selling or sharing
of data. Crash reports are shown only on your phone, for you to copy if you want to.

## Deleting your data
Delete a passkey in the app, or uninstall the app to delete everything. Also remove the passkey from
the website's account settings; deleting it on the phone doesn't tell the website.

## Contact
Open an issue at https://github.com/aman-dhakar-191/passkey-provider-android/issues.
