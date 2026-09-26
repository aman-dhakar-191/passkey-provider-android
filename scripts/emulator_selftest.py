#!/usr/bin/env python3
"""Runs the in-app passkey self-test on an emulator and drives the system UI through it.

Used by .github/workflows/emulator.yml. Installs the debug APK, sets a screen-lock PIN, makes this
app the (preferred) credential provider, starts the self-test (create a passkey, then sign in with
it and verify the signature) and taps through Android's passkey sheets and PIN prompts. Screenshots, the app's activity log and logcat are written to
emulator-output/. Exits non-zero unless the app logs "Self-test passed".
"""
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PKG = "io.github.amandhakar.passkey.debug"
SERVICE = f"{PKG}/io.github.amandhakar.passkey.provider.PasskeyProviderService"
ACTIVITY = f"{PKG}/io.github.amandhakar.passkey.ui.MainActivity"
# BUILD_TYPE=minified tests the build with release's R8 settings.
BUILD_TYPE = os.environ.get("BUILD_TYPE", "debug")
APK = f"app/build/outputs/apk/github/{BUILD_TYPE}/app-github-{BUILD_TYPE}.apk"
PIN = "1234"
OUT = "emulator-output"
TIMEOUT_S = 240

# Buttons to press, in priority order. Never press anything that cancels.
PROVIDER = re.compile(r"^Passkey (Vault|Provider)$", re.I)
TARGETS = [
    re.compile(r"^(Create|Create passkey|Continue|Save|Next|OK|Done|Sign in|Use passkey)$", re.I),
    re.compile(r"^(Use PIN|Use password|Use screen lock)$", re.I),
    PROVIDER,
    re.compile(r"^self-test$", re.I),  # the test passkey's entry in the sign-in sheet
]
AVOID = re.compile(r"cancel|close|not now|dismiss", re.I)
last_pin = 0.0


def run(*args):
    result = subprocess.run(["adb", *args], capture_output=True, text=True)
    return result.stdout + result.stderr


def shell(cmd):
    return run("shell", cmd)


def activity_log():
    if BUILD_TYPE == "debug":
        return shell(f"run-as {PKG} cat files/provider_errors.txt")
    # Not debuggable, so run-as can't read the app's files; SELF_TEST builds copy the log to logcat.
    return run("logcat", "-d", "-s", "PasskeyVault:I")


def ui_nodes():
    shell("uiautomator dump /sdcard/ui.xml")
    raw = shell("cat /sdcard/ui.xml")
    start = raw.find("<?xml")
    if start < 0:
        return []
    try:
        root = ET.fromstring(raw[start:])
    except ET.ParseError:
        return []
    return list(root.iter("node"))


def center(node):
    x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.get("bounds", "[0,0][0,0]")))
    return (x1 + x2) // 2, (y1 + y2) // 2


def label(node):
    return (node.get("text") or node.get("content-desc") or "").strip()


def act(nodes):
    """Performs one UI step. Returns a description of what was done, or None."""
    # Emulators often show "<app> isn't responding" (usually the launcher). Waiting just brings it back and
    # the dialog swallows the next tap, so close that app instead (never our own).
    if any("isn't responding" in label(n) or "isn’t responding" in label(n) for n in nodes):
        ours = any("Passkey" in label(n) and "responding" in label(n) for n in nodes)
        for node in nodes:
            if label(node).lower() == ("wait" if ours else "close app"):
                x, y = center(node)
                shell(f"input tap {x} {y}")
                return f"answered 'not responding' dialog with '{label(node)}'"
    # The screen can lock (a PIN is set); unlock it with the test PIN.
    if any(label(n) == "Device locked" for n in nodes):
        shell("input keyevent 224")
        shell("wm dismiss-keyguard")
        time.sleep(1)
        shell(f"input text {PIN}")
        shell("input keyevent 66")
        return "unlocked the screen"
    for node in nodes:
        if node.get("class", "").endswith("EditText") and node.get("password") == "true":
            # The prompt takes a moment to close after the PIN; typing it again then lands on the next sheet
            # and cancels it. So wait before treating a PIN field as a new prompt.
            global last_pin
            if time.time() - last_pin < 8:
                return None
            x, y = center(node)
            shell(f"input tap {x} {y}")
            shell(f"input text {PIN}")
            shell("input keyevent 66")
            last_pin = time.time()
            return "entered PIN"
    # Google's "create on another device" (QR code) path cannot finish on an emulator; only follow it
    # if this provider is not offered at all, which the log then shows.
    on_hybrid_screen = any("another device" in label(n).lower() for n in nodes)
    # On our own home screen, wait: its texts (app name, passkey names) match the patterns below, and any tap
    # there while Android's sheet is opening cancels the sheet.
    # The button can be missing while the screen is still drawing, so also check the status line and heading.
    if any(label(n) == "Scan QR code" or label(n).startswith("Passkey Vault is ") or label(n).startswith("Passkeys (")
           for n in nodes):
        return None
    for pattern in TARGETS:
        if on_hybrid_screen and pattern is not PROVIDER:
            continue
        for node in nodes:
            text = label(node)
            if text and pattern.search(text) and not AVOID.search(text):
                x, y = center(node)
                shell(f"input tap {x} {y}")
                return f"tapped '{text}'"
    return None


def main():
    os.makedirs(OUT, exist_ok=True)
    print(run("install", "-r", APK))
    # The minified build has the self-updater on, which asks for this at launch; the dialog would cover the sheet.
    shell(f"pm grant {PKG} android.permission.POST_NOTIFICATIONS")
    print("set PIN:", shell(f"locksettings set-pin {PIN}").strip())
    shell(f"settings put secure credential_service {SERVICE}")
    shell(f"settings put secure credential_service_primary {SERVICE}")
    print("credential_service =", shell("settings get secure credential_service").strip())
    print("credential_service_primary =", shell("settings get secure credential_service_primary").strip())
    # Credential Manager picks up a newly installed + enabled provider asynchronously; starting the
    # request straight away races it and the provider is left out of the request.
    time.sleep(20)
    dump = shell("dumpsys credential")
    print("===== dumpsys credential =====\n" + dump[:4000])
    shell("logcat -c")
    print(shell(f"am start -W -n {ACTIVITY} --ez run_self_test true"))

    deadline = time.time() + TIMEOUT_S
    step = 0
    log = ""
    while time.time() < deadline:
        time.sleep(3)
        step += 1
        log = activity_log()
        if "Self-test passed" in log or "Self-test failed" in log:
            break
        with open(f"{OUT}/step-{step:02d}.png", "wb") as f:
            f.write(subprocess.run(["adb", "exec-out", "screencap", "-p"], capture_output=True).stdout)
        nodes = ui_nodes()
        visible = [label(n) for n in nodes if label(n)]
        done = act(nodes)
        print(f"step {step}: {done or 'waiting'} | on screen: {visible[:12]}")

    with open(f"{OUT}/final.png", "wb") as f:
        f.write(subprocess.run(["adb", "exec-out", "screencap", "-p"], capture_output=True).stdout)
    with open(f"{OUT}/logcat.txt", "w") as f:
        f.write(run("logcat", "-d"))
    with open(f"{OUT}/activity-log.txt", "w") as f:
        f.write(log)

    print("===== Credential-related logcat =====")
    for line in run("logcat", "-d").splitlines():
        if re.search(r"credential|passkey|CredentialManager|amandhakar", line, re.I):
            print(line)
    # Last, so it is at the end of the job log.
    print(f"\n===== App activity log, {BUILD_TYPE} build =====\n" + log)
    sys.exit(0 if "Self-test passed" in log else 1)


if __name__ == "__main__":
    main()
