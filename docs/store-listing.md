# Store listing: Passkey Vault (draft)

Drafts for Google Play Console and Indus Appstore. Check each store's current limits before pasting.

## Names
- **App name (Play, max 30 chars):** Passkey Vault
  - Search Play first; if the name is taken or too similar, alternatives are "Passkey Vault: Device Keys"
    or another name. Changing the store name never affects updates (the package name does).
- **Package:** `io.github.amandhakar.passkey` (cannot change after the first upload)

## Short description (Play, max 80 chars)
Passkeys kept on your phone. Sign in to apps, browsers and computers by fingerprint.

## Full description
Passkey Vault stores your passkeys securely on your phone and signs you in with your fingerprint or
screen lock, with no passwords to remember or type.

• Works with apps and browsers on your phone through Android's passkey system (Android 14+).
• Sign in on a computer: choose "Use a phone or tablet" and scan the QR code.
• Keys are created in your phone's secure hardware and never leave it.
• Anti-phishing: a passkey only works on the website it was created for, and only trusted browsers and
  verified apps can use it.
• No account, no cloud, no tracking, no ads.

Passkeys are stored only on this phone and aren't synced or backed up. Keep another way to sign in to
important accounts.

Set up: install, then choose Passkey Vault under Settings → Passwords, passkeys & accounts.

## Category and contact
- Category: Tools (or Productivity)
- Contact email: (add yours)
- Privacy policy URL: https://github.com/aman-dhakar-191/passkey-provider-android/blob/main/PRIVACY.md

## Google Play "Data safety" answers (store build)
- Does the app collect or share any of the required user data types? **No**
  - Passkeys and account names stay on the device and are never sent anywhere. Play only counts data
    that leaves the device.
- Is data encrypted in transit? Yes (all requests use HTTPS). Users can request deletion: uninstall
  or delete in-app.
- **To check yourself before submitting:** the QR scanner uses Google's code scanner SDK (Google Play
  services). Look at that SDK's data disclosure in Google's documentation and add anything it lists.

## Screenshots to take (phone, portrait)
1. Main screen with a few passkeys grouped by site
2. Android's passkey sheet offering Passkey Vault
3. Fingerprint prompt during sign-in
4. "Sign in on a computer" card / QR scanning

## Content rating
Answer the questionnaire: no user-generated content, no ads, no in-app purchases; a utility app.

## Signing
- **Google Play:** during setup choose *Play App Signing*. Either let Google create the app signing key
  and upload with your own key, or use "Export and upload a key from Java keystore" to reuse the GitHub
  key, so the GitHub and Play versions have the same signature and can update each other.
- **Indus Appstore:** upload the signed APK/AAB from the Store release workflow.
