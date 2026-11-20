#!/usr/bin/env bash
# Proves what the builds do NOT contain.
#  - No build (store or GitHub) can update itself: no install-packages permission, none of the old updater
#    classes, no package installer, no GitHub API. Updates come from the stores or the private app store.
#  - The store build (Google Play, Indus Appstore) also has none of the GitHub-only extras, which are the
#    notification permission and WorkManager (Backup & recovery reminders).
# The GitHub build is checked the other way round for the extras, so a broken check can't pass silently.
#
# Usage: scripts/check-store-build.sh <store .apk> [<store .aab>] [--github <github .apk>]
set -euo pipefail

BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
# Nowhere.
PERMISSIONS=(android.permission.REQUEST_INSTALL_PACKAGES)
CODE=(
  'Lio/github/amandhakar/passkey/update/UpdateWorker;'
  'Lio/github/amandhakar/passkey/update/InstallResultReceiver;'
  # Writing an install session; only needed to install an APK. (Play services only lists sessions.)
  'Landroid/content/pm/PackageInstaller$Session;'
  'api.github.com'
)
# GitHub build only.
EXTRA_PERMISSIONS=(android.permission.POST_NOTIFICATIONS)
EXTRA_CODE=('Landroidx/work/')

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Prints every pattern found in the dex files of an .apk or .aab.
found_code() {
  local file="$1"; shift
  local dir="$work/$(basename "$file")"
  mkdir -p "$dir"
  unzip -q -o "$file" '*.dex' -d "$dir"
  for pattern in "$@"; do
    if find "$dir" -name '*.dex' -exec grep -aqF "$pattern" {} + 2>/dev/null; then echo "$pattern"; fi
  done
}

found_permissions() {
  local dump file="$1"; shift
  dump="$("$BT/aapt2" dump permissions "$file")"
  for permission in "$@"; do
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
  hits="$(found_code "$file" "${CODE[@]}" "${EXTRA_CODE[@]}")"
  if [[ "$file" == *.apk ]]; then hits+=$'\n'"$(found_permissions "$file" "${PERMISSIONS[@]}" "${EXTRA_PERMISSIONS[@]}")"; fi
  hits="$(sed '/^$/d' <<<"$hits")"
  if [ -n "$hits" ]; then
    echo "::error::$file contains update code, GitHub-only code or permissions:"; echo "$hits" | sed 's/^/  /'
    failed=1
  else
    echo "OK: $file has no update code, WorkManager or GitHub-only permissions"
  fi
done

if [ -n "$github" ]; then
  hits="$(found_code "$github" "${CODE[@]}" "${EXTRA_CODE[@]}")"$'\n'"$(found_permissions "$github" "${PERMISSIONS[@]}" "${EXTRA_PERMISSIONS[@]}")"
  for forbidden in "${PERMISSIONS[@]}" "${CODE[@]}"; do
    if grep -qxF "$forbidden" <<<"$hits"; then
      echo "::error::The GitHub build $github contains update code or permissions: $forbidden"
      failed=1
    fi
  done
  for expected in "${EXTRA_PERMISSIONS[@]}" "${EXTRA_CODE[@]}"; do
    if ! grep -qxF "$expected" <<<"$hits"; then
      echo "::error::Check is broken: expected '$expected' in the GitHub build $github"
      failed=1
    fi
  done
  [ "$failed" = 1 ] || echo "OK: $github has no update code, and the same checks find its extras"
fi

exit "$failed"
