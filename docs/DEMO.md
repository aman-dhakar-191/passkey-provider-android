# Passkey Demo

Passkey Demo is a small test app for trying passkeys the way other apps use them. It is not Passkey Vault, and it is for testing, not for everyday use.

Most apps do not use passkeys in a browser. They ask Android directly, or they show their login page as a web page inside the app. The demo does both, so you can see whether your passkey app handles each one.

## What it does

- **In the app:** create a passkey and sign in, straight from the demo's own screen.
- **In a web page inside the app:** the same, from a login page shown inside the app, or any other page you type in.
- **Checks every answer:** the demo plays the website. It checks what the passkey app sends back the way a real website must, and lists each check as passed or failed. You can copy the results.
- **Checks the site:** one button tells you whether the site has been set up to allow the demo, and what is missing if not.
- **Updates itself:** one button looks for a newer demo and installs it.

## Get it

- Open the [releases page](https://github.com/aman-dhakar-191/passkey-provider-android/releases) and pick the newest release named **Passkey Demo**. Demo releases are marked as pre-releases on purpose, so they never get mixed up with Passkey Vault.
- Download the file ending in `.apk` and open it. Android asks you to allow installing from your browser or files app.
- You need Android 14 or newer, and Passkey Vault chosen as your passkey app in Settings, under Passwords, passkeys and accounts.

## Why a site is needed

Passkey Vault only lets an app use a website's passkeys if the website says the app may. The website does that with a small file that names the app and the key it is signed with, at the root of the site's address. The demo's site is https://aman-passkey-demo.web.app and the file is at https://aman-passkey-demo.web.app/.well-known/assetlinks.json. Without it, Passkey Vault refuses on purpose. That protects you from an app pretending to belong to a site.

Each demo release includes that file, called `assetlinks.json`. The demo's **Check site setup** button tells you whether the site is publishing it.

## Try a login page in a browser

The demo's login page is a real web page on the demo's site: [open the demo login page](https://aman-passkey-demo.web.app/). In the demo app you can open the same address inside the app, which is how apps that show their login page as a web page behave. Passkeys made there are for the site aman-passkey-demo.web.app.

## Questions

Write to amandhaker191@gmail.com or open an issue on the [source code page](https://github.com/aman-dhakar-191/passkey-provider-android).
