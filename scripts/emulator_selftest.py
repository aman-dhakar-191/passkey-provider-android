#!/usr/bin/env python3
"""Runs the in-app passkey self-test on an emulator and drives the system UI through it.

Used by .github/workflows/emulator.yml. Installs the debug APK, sets a screen-lock PIN, makes this
app the (preferred) credential provider, starts the self-test and then taps through Android's
passkey sheet and the PIN prompt. Screenshots, the app's activity log and logcat are written to
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
APK = "app/build/outputs/apk/debug/app-debug.apk"
PIN = "1234"
OUT = "emulator-output"
TIMEOUT_S = 150

# Buttons to press, in priority order. Never press anything that cancels.
TARGETS = [
    re.compile(r"^Passkey Provider", re.I),
    re.compile(r"^(Create|Create passkey|Continue|Save|Next|OK|Done)$", re.I),
    re.compile(r"^(Use PIN|Use password|Use screen lock)$", re.I),
]
AVOID = re.compile(r"cancel|close|not now|dismiss", re.I)


def run(*args):
    result = subprocess.run(["adb", *args], capture_output=True, text=True)
    return result.stdout + result.stderr


def shell(cmd):
    return run("shell", cmd)


def activity_log():
    return shell(f"run-as {PKG} cat files/provider_errors.txt")


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
    for node in nodes:
        if node.get("class", "").endswith("EditText") and node.get("password") == "true":
            x, y = center(node)
            shell(f"input tap {x} {y}")
            shell(f"input text {PIN}")
            shell("input keyevent 66")
            return "entered PIN"
    for pattern in TARGETS:
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
    print("set PIN:", shell(f"locksettings set-pin {PIN}").strip())
    shell(f"settings put secure credential_service {SERVICE}")
    shell(f"settings put secure credential_service_primary {SERVICE}")
    print("credential_service =", shell("settings get secure credential_service").strip())
    print("credential_service_primary =", shell("settings get secure credential_service_primary").strip())
    shell("logcat -c")
    print(shell(f"am start -W -n {ACTIVITY} --ez run_self_test true"))

    deadline = time.time() + TIMEOUT_S
    step = 0
    log = ""
    while time.time() < deadline:
        time.sleep(3)
        step += 1
        log = activity_log()
        if "Self-test passed" in log or "Self-test failed" in log or "Self-test cancelled" in log \
                or "found no service" in log:
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

    print("\n===== App activity log (newest first) =====\n" + log)
    print("===== Credential-related logcat =====")
    for line in run("logcat", "-d").splitlines():
        if re.search(r"credential|passkey|CredentialManager|amandhakar", line, re.I):
            print(line)
    sys.exit(0 if "Self-test passed" in log else 1)


if __name__ == "__main__":
    main()
