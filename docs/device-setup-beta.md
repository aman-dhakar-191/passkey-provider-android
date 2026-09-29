# Device-setup transfer (beta)

GitHub builds include an experimental `DeviceSetupService`
(`app/src/github/java/.../devicesetup/`). It exists to **observe** what Android does when a new phone is
set up from an old one ("Copy apps & data"). It never creates, deletes, exports or stores a passkey. Store
builds don't include it.

Library: `androidx.credentials.providerevents:providerevents` and `providerevents-play-services`
`1.0.0-beta01`. This library needs `androidx.credentials` 1.6.0, so GitHub builds use 1.6.0; store builds
stay on 1.5.0.

## The three calls

Google Play services runs device setup and is the only allowed caller. The androidx library checks that the
caller is Play services before our code runs. The method names describe the transfer from the *system's*
side:

| Call | Runs on | Android asks | Passkey Vault answers |
|---|---|---|---|
| `onGetCredentialTransferCapabilities` | old phone | "How many credentials can you transfer, and how big?" (shown during setup) | 0 transferable, with the size of an empty CXF document |
| `onImportCredentialsRequest` | old phone | "Give me your credentials as CXF" (Android *imports from* us) | A valid CXF header with no accounts |
| `onExportCredentialsRequest` | new phone | "Here are credentials from the old phone as CXF" (Android *exports into* us) | Per type: 0 stored; complete passkeys "ignored", incomplete ones "failed" |

These calls only arrive on a phone where Passkey Vault is turned on as a passkey service
(Settings → Passwords, passkeys & accounts).

## Why existing passkeys can't move

A CXF passkey needs its private key (`key`, as PKCS#8 bytes). Passkey Vault creates every private key
inside the Android Keystore, in StrongBox or the TEE, as non-exportable, and using it needs your fingerprint
or screen lock. The Keystore has no way to hand out those bytes, to Passkey Vault or anyone else. That is
the app's core security promise.

So the beta reports every passkey as not transferable. It does not:

- fake a successful transfer,
- make keys exportable, or
- switch to software keys.

Sending a passkey without its key would only give the new phone a record it can never sign in with.

What *could* work later:

- **A passkey from another app:** if Android delivers one to the new phone with its key, it could be
  imported into the new phone's Keystore. That would give a new hardware-protected copy, though not a
  StrongBox-generated one.
- **Passkeys created on the new phone:** new passkeys made there after setup work as today.

## Who protects what

- **Android / Google Play services:**
  - verifying and pairing the two phones and encrypting everything sent between them (no relay server of
    ours is involved);
  - making sure only Play services can call this service;
  - handing the CXF document over through a private file link.
- **Passkey Vault:**
  - deciding what may leave the phone (nothing: the keys are hardware-bound);
  - never logging credential material;
  - checking what arrives;
  - in a real import, protecting received keys (Keystore, user authentication) and wiping them from memory.

## Build and install

Two ways:

- **Test build (recommended; nothing is published):** download the `debug-apk` artifact from the PR's
  *CI* run and install it on both phones.
  - It is a separate app ("Passkey Vault", package `io.github.amandhakar.passkey.debug`) next to your
    real one.
  - Create one or two passkeys in it on the old phone, for example at webauthn.io. They are hardware-bound
    exactly like the real app's.
  - Turn it on as a passkey service in Settings.
- **Your real app and passkeys:** needs a release-signed build installed over the existing one. That
  means a new *Release*, which also offers the update to every GitHub user. The beta is read-only, so this
  is safe, but it is a public release.

On the new phone, install the same build and turn it on as a passkey service. If the setup wizard doesn't
give you the chance first, do it right after setup.

## Test: old phone → new phone

1. **Old phone:**
   - Passkey Vault (this build) is installed with at least one passkey.
   - It is turned on as a passkey service.
   - USB debugging is on, if you want logcat.
2. Start logcat on the old phone: `adb logcat -s PasskeyDeviceSetup EventsPlayServices ProviderFactory`
3. **New phone:** factory reset, or use a phone that hasn't been set up. In the setup wizard, choose to
   copy apps & data from the old phone. The cable and the wireless options both go through Play services.
4. Continue until setup finishes. Watch the old phone's log during the "what to copy" and copy steps.
5. After setup, on the new phone:
   - install or open Passkey Vault;
   - turn it on as a passkey service;
   - run `adb logcat -s PasskeyDeviceSetup` on the new phone too.
6. On both phones, open Passkey Vault → activity log. Every beta entry starts with
   `Device setup (beta):`.

## Logs to look for (tag `PasskeyDeviceSetup`)

- **Old phone:**
  - `Transfer capabilities requested (old phone), caller com.google.android.gms, types [...]`: Android
    asked what we can transfer. The listed types show what setup supports.
  - `N passkey(s) on this phone:` with one line per passkey, like
    `1. example.com: StrongBox, user auth yes, exportable no → left out`. This shows where each key lives.
  - `CXF shape it would need: {type: passkey, ... key: <not available: ...>}`
  - `Credentials requested from this phone (old phone)` and `Returned CXF document: 0 passkeys ...`:
    Android went on to ask for the credentials themselves.
- **New phone:**
  - `Credentials delivered to this phone (new phone), ... characters of CXF`
  - `Delivered document outline:`: the structure Android delivered, with values replaced by their sizes.
  - `CXF version ...: N account(s), N item(s), N passkey(s), other types {...}`
  - `Answered: 0 stored; ...`
- **Library (`EventsPlayServices`):** `Not authorized` means something other than Play services called.
  Other messages mean a file or JSON error.

## What proves it works

- **The service is really called during setup:** any `PasskeyDeviceSetup` line with
  `caller com.google.android.gms`.
- **Android wants credentials, not just a count:** `Credentials requested from this phone` appears on the
  old phone.
- **Android delivers credentials to providers:** `Credentials delivered to this phone` appears on the new
  phone, and its outline shows the real CXF structure Android uses.
- **Android reacts to "0 transferable":**
  - neither line appears → Android probably skipped us after the capabilities call;
  - no line at all → our service wasn't bound (see limitations).

## Known limitations

- **Android and library version:**
  - The library is beta (`1.0.0-beta01`), and the Play services side isn't public.
  - Which Android and Play services versions actually call providers during setup isn't documented.
    Expect no calls on some phones.
- **Passkey service must be on:** the service is only bound for a provider that's turned on as a passkey
  service, and a new phone mid-setup has nothing turned on yet. So the new-phone side may never get a
  call during the first setup.
- **Passkeys from this app never move:** they are hardware-bound. This is by design and won't change.
- **Nothing is stored on import:** the beta only reports what arrived. Storing would need a Keystore
  import path and its own security review.
