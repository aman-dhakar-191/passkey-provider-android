#!/usr/bin/env python3
"""Fails the build if a release APK's merged manifest opens up the app.

Checks, on the final manifest (after libraries are merged in):
  - Only the components listed in OUR_EXPORTED are reachable by other apps, each with the permission listed
    there. A library's exported component must be guarded by a platform permission (e.g. DUMP).
  - No dangerous permission (DENIED_PERMISSIONS) was added, e.g. by a new library.
  - Not debuggable, backups off, no cleartext HTTP.
The full component and permission lists are printed, so a change shows up in the CI log.

Usage: scripts/check-manifest.py <release .apk>...
"""
import glob
import os
import re
import subprocess
import sys

ANDROID = "http://schemas.android.com/apk/res/android:"
COMPONENTS = {"activity", "activity-alias", "service", "receiver", "provider"}
APP = "io.github.amandhakar.passkey."

# Our components that other apps may start, and the permission the caller must hold (None = anyone).
OUR_EXPORTED = {
    APP + "ui.MainActivity": None,  # the launcher icon
    # Only the system holds BIND_CREDENTIAL_PROVIDER_SERVICE, so only Android itself can bind.
    APP + "provider.PasskeyProviderService": "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE",
}

DENIED_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW",  # overlays over other apps
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",  # QR scanning runs in Google Play services, not in this app
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_CREDENTIALS",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_DEVICE_ADMIN",
}


class Element:
    def __init__(self, tag):
        self.tag = tag
        self.attrs = {}
        self.children = []

    def get(self, name):
        return self.attrs.get(name)

    def iter(self):
        yield self
        for child in self.children:
            yield from child.iter()


def parse_xmltree(text):
    """Parses `aapt2 dump xmltree` output into Elements. Attribute values: strings unquoted, the rest raw."""
    root = Element("#document")
    stack = [(-1, root)]
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip())
        item = line.strip()
        if item.startswith("E: "):
            while stack[-1][0] >= indent:
                stack.pop()
            element = Element(item[3:].split(" ", 1)[0])
            stack[-1][1].children.append(element)
            stack.append((indent, element))
        elif item.startswith("A: "):
            while stack[-1][0] >= indent:
                stack.pop()
            match = re.match(r"A: (.+?)(?:\(0x[0-9a-f]+\))?=(.*)$", item)
            if not match:
                continue
            name, value = match.groups()
            name = name[len(ANDROID):] if name.startswith(ANDROID) else name
            quoted = re.match(r'"(.*?)"(?: \(Raw: .*\))?$', value)
            stack[-1][1].attrs[name] = quoted.group(1) if quoted else value
    return root


def is_true(value):
    # aapt2 prints booleans as true/false, older versions as (type 0x12)0xffffffff / 0x0.
    return value is not None and (value == "true" or value.endswith("0xffffffff"))


def full_name(name, package):
    return package + name if name.startswith(".") else name


def check(apk):
    build_tools = sorted(glob.glob(os.path.join(os.environ["ANDROID_HOME"], "build-tools", "*")))[-1]
    dump = subprocess.run(
        [os.path.join(build_tools, "aapt2"), "dump", "xmltree", "--file", "AndroidManifest.xml", apk],
        check=True, capture_output=True, text=True,
    ).stdout
    root = parse_xmltree(dump)
    manifest = next(e for e in root.iter() if e.tag == "manifest")
    package = manifest.get("package")
    application = next(e for e in root.iter() if e.tag == "application")
    errors = []

    print(f"== {apk} ({package})")
    if is_true(application.get("debuggable")):
        errors.append("application is debuggable")
    if application.get("allowBackup") is None or is_true(application.get("allowBackup")):
        errors.append("allowBackup is not false")
    if is_true(application.get("usesCleartextTraffic")):
        errors.append("cleartext HTTP is allowed")

    permissions = sorted(e.get("name") for e in root.iter() if e.tag in ("uses-permission", "uses-permission-sdk-23"))
    print("permissions:\n  " + "\n  ".join(permissions))
    errors += [f"dangerous permission {p}" for p in permissions if p in DENIED_PERMISSIONS]

    found_ours = set()
    print("exported components:")
    for element in application.iter():
        if element.tag not in COMPONENTS:
            continue
        name = full_name(element.get("name") or "", package)
        exported = element.get("exported")
        has_filter = any(child.tag == "intent-filter" for child in element.children)
        # Without android:exported, a component with an intent filter is exported (and pre-S builds allowed that).
        if not (is_true(exported) or (exported is None and has_filter)):
            continue
        permission = element.get("permission")
        print(f"  {element.tag} {name} (permission: {permission})")
        if name.startswith(APP):
            if name not in OUR_EXPORTED:
                errors.append(f"{name} is exported but not listed in OUR_EXPORTED")
            elif permission != OUR_EXPORTED[name]:
                errors.append(f"{name} needs permission {OUR_EXPORTED[name]}, has {permission}")
            else:
                found_ours.add(name)
        elif not (permission or "").startswith("android.permission."):
            errors.append(f"library component {name} is exported without a platform permission")

    # The parser must have found what we know is there, so a broken parser can't pass silently.
    for name in sorted(set(OUR_EXPORTED) - found_ours):
        errors.append(f"check is broken: expected exported component {name} not found")

    for error in errors:
        print(f"::error::{apk}: {error}")
    if not errors:
        print("OK")
    return not errors


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    results = [check(apk) for apk in sys.argv[1:]]
    sys.exit(0 if all(results) else 1)
