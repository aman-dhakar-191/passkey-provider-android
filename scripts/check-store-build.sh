#!/usr/bin/env bash
# Proves the store build (Google Play, Indus Appstore) contains no self-update code: no install-packages
# or notification permission, none of the updater classes (UpdateManager itself may be inlined by R8, so
# the checks look for what it uses), no package installer, WorkManager or GitHub API.
# The same checks run against the GitHub build expecting the opposite, so a broken check can't pass silently.
#
# Usage: scripts/check-store-build.sh <store .apk> [<store .aab>] [--github <github .apk>]
set -euo pipefail

BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
PERMISSIONS=(android.permission.REQUEST_INSTALL_PACKAGES android.permission.POST_NOTIFICATIONS)
CODE=(
  'Lio/github/amandhakar/passkey/update/UpdateWorker;'
  'Lio/github/amandhakar/passkey/update/InstallResultReceiver;'
  # Writing an install session; only needed to install an APK. (Play services only lists sessions.)
  'Landroid/content/pm/PackageInstaller$Session;'
  'Landroidx/work/'
  'api.github.com'
)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Prints every pattern found in the dex files of an .apk or .aab.
found_code() {
  local dir="$work/$(basename "$1")"
  mkdir -p "$dir"
  unzip -q -o "$1" '*.dex' -d "$dir"
  for pattern in "${CODE[@]}"; do
    if find "$dir" -name '*.dex' -exec grep -aqF "$pattern" {} + 2>/dev/null; then echo "$pattern"; fi
  done
}

found_permissions() {
  local dump
  dump="$("$BT/aapt2" dump permissions "$1")"
  for permission in "${PERMISSIONS[@]}"; do
    if grep -qF "$permission" <<<"$dump"; then echo "$permission"; fi
  done
}

failed=0
store=()
github=""
while [ $# -gt 0 ]; do
  case "$1" in
    --github) github="$2"; shift 2 ;;
    *) store+=("$1"); shift ;;
  esac
done

for file in "${store[@]}"; do
  hits="$(found_code "$file")"
  if [[ "$file" == *.apk ]]; then hits+=$'\n'"$(found_permissions "$file")"; fi
  hits="$(sed '/^$/d' <<<"$hits")"
  if [ -n "$hits" ]; then
    echo "::error::$file contains update code or permissions:"; echo "$hits" | sed 's/^/  /'
    failed=1
  else
    echo "OK: $file has no update code or permissions"
  fi
done

if [ -n "$github" ]; then
  hits="$(found_code "$github")"$'\n'"$(found_permissions "$github")"
  for expected in "${PERMISSIONS[@]}" "${CODE[@]}"; do
    if ! grep -qxF "$expected" <<<"$hits"; then
      echo "::error::Check is broken: expected '$expected' in the GitHub build $github"
      failed=1
    fi
  done
  [ "$failed" = 1 ] || echo "OK: the same checks find the updater in $github"
fi

exit "$failed"
