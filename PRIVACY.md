# Privacy policy: Passkey Vault

This policy explains what the Passkey Vault Android app and its website do with your information. It
applies to every version of the app: the one from GitHub and the ones from app stores (Indus Appstore,
Google Play).

**In short:** your passkeys and everything about them stay on your phone. The developer never receives
any of it. There is no account, no server, no analytics, no ads and no tracking.

## 1. Who we are
Passkey Vault is made by **Aman Dhakar**, an individual developer in India ("we", "us"). For any
question about this policy or your data, email **amandhaker191@gmail.com** or open an issue at
https://github.com/aman-dhakar-191/passkey-provider-android/issues.

## 2. Information the app keeps on your phone
The app stores the following **only on your phone**, in its private storage and in the phone's Android
Keystore. We can't see, access or copy any of it.

- **Passkeys (private keys).** Each one is created inside the Android Keystore, in secure hardware
  (StrongBox) where the phone has it. It can't be exported from the phone by the app, by you or by us.
- **Passkey details.** For each passkey: the website or app it belongs to, the account ID, account name
  and display name the website provided, when it was created and last used, and a name you give it.
- **Activity log.** Recent passkey requests (which app asked, for which website, the result, and any
  error), kept so you can troubleshoot. It holds at most the last 30 entries. You can copy or clear it.
- **Crash reports.** If the app crashes, the error details are shown to you on the phone. They are
  never sent anywhere.

## 3. Information we collect
**None.** The app has no account and sends no personal data to us or to anyone else. We don't use
analytics, advertising or crash-reporting services.

## 4. Internet connections the app makes
The app only downloads public files. It never uploads your passkeys or passkey details.

- **Google's list of trusted browsers**
  (`https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json`), about once a day, to check that
  a browser asking for a passkey is genuine.
- **A website's `/.well-known/assetlinks.json`**, when an app (not a browser) asks for a passkey, to
  check that the website allows that app to use its passkeys.
- **GitHub version only:** the latest release information from GitHub once a day, and the new version
  if you choose to update. App-store versions don't do this; the store handles updates.

Like any internet connection, these reveal your phone's IP address to the server that answers (Google,
the website, or GitHub), under that company's own privacy policy.

## 5. Permissions
- **Internet:** for the downloads in section 4.
- **Biometrics:** to confirm it's you, with your fingerprint (or other strong biometric) or screen
  lock, before a passkey is created or used. Android does the check; the app never receives your
  fingerprint.
- **Notifications (GitHub version only):** to tell you when an update is available.
- **Install apps (GitHub version only):** to install an update you chose to download.

The **Scan QR code** button uses Google's code scanner, part of Google Play services, so the app itself
doesn't need camera permission and never receives camera images; it only gets the scanned text.

## 6. Other companies' services
- **Google Play services** runs the QR-code scanner and, when you sign in on a computer, the Bluetooth
  and connection step of that sign-in. Google's privacy policy applies:
  https://policies.google.com/privacy.
- **Android's Credential Manager** passes passkey requests between websites or apps and Passkey Vault.
- **Websites and apps you sign in to** receive your passkey's public key and sign-in signatures, which
  is how passkeys work. What they do with your account is covered by their own privacy policies.
- **The store you installed from** (GitHub, Indus Appstore or Google Play) handles downloads under its
  own privacy policy.

## 7. Sharing and selling
We don't share, sell or rent any information, because we don't have any.

## 8. Security
- Passkeys are created and used inside the phone's secure hardware, and each use needs your
  fingerprint or screen lock.
- Before a passkey is used, the app checks that the request comes from a trusted browser or from an app
  the website has approved. A passkey only works on the website it was created for, which protects you
  from phishing sites.
- Passkeys and their details are excluded from Android's cloud backups and device-to-device transfers.
- All downloads use HTTPS.

## 9. Keeping and deleting data
Everything stays on your phone until you delete it:
- **Delete one passkey** in the app (🗑). Also remove it from the website's account settings, because
  deleting it on the phone doesn't tell the website.
- **Clear the activity log** in the app.
- **Uninstall the app** to delete all passkeys and data. Removing your phone's screen lock may also make
  Android delete the passkeys' keys.

Passkeys aren't backed up or synced. If you lose or reset your phone, its passkeys are gone, so keep
another way to sign in to your important accounts.

## 10. Your rights
Under India's Digital Personal Data Protection Act, 2023, the GDPR and similar laws, you can ask to
access, correct or erase your personal data, withdraw consent, and (in India) nominate someone to act
for you. Because all data is on your phone and under your control, you can do all of this in the app
yourself. We hold no data about you to access or erase.

**Grievance contact:** Aman Dhakar, amandhaker191@gmail.com. We reply within 30 days. In India, if
you're not satisfied, you can complain to the Data Protection Board of India; in the EU, to your data
protection authority.

## 11. Children
The app is suitable for all ages and collects no information from anyone, including children.

## 12. This website
The website is hosted by GitHub Pages. We use no cookies, analytics or trackers on it. GitHub may record
visitors' IP addresses for security, under the GitHub privacy statement:
https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement.

## 13. Changes to this policy
If this policy changes, the new version is published at the same address with its date. Every past
version is kept in the project's public history. If a change affects how the app handles your data, it
will also be listed in the release notes.
