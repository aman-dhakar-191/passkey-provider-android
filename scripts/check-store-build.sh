#!/usr/bin/env bash
# Proves what each build contains:
#  - Neither build can install apps or update itself: no install-packages permission, no package-installer
#    session code, no GitHub API. Updates come from the store the app was installed from (Google Play, Indus
#    Appstore, or the private store the GitHub build is published to).
#  - The store build (Google Play, Indus Appstore) has none of the GitHub build's extras: no notification
#    permission and no WorkManager, which only Backup & recovery's reminders use.
# The GitHub build is checked for those extras too, so a broken check can't pass silently.
#
# Usage: scripts/check-store-build.sh <store .apk> [<store .aab>] [--github <github .apk>]
set -euo pipefail

BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
# Never in any build.
NEVER_PERMISSIONS=(android.permission.REQUEST_INSTALL_PACKAGES)
NEVER_CODE=(
  # Writing an install session; only needed to install an APK. (Play services only lists sessions.)
  'Landroid/content/pm/PackageInstaller$Session;'
  'api.github.com'
)
# In the GitHub build only.
GITHUB_PERMISSIONS=(android.permission.POST_NOTIFICATIONS)
GITHUB_CODE=(
  'Landroidx/work/'
  'Lio/github/amandhakar/passkey/recovery/BackupReminderWorker;'
)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Prints each of the given patterns found in the dex files of an .apk or .aab.
found_code() {
  local file="$1"; shift
  local dir="$work/$(basename "$file")"
  mkdir -p "$dir"
  unzip -q -o "$file" '*.dex' -d "$dir"
  for pattern in "$@"; do
    if find "$dir" -name '*.dex' -exec grep -aqF "$pattern" {} + 2>/dev/null; then echo "$pattern"; fi
  done
}

# Prints each of the given permissions the .apk declares.
found_permissions() {
  local file="$1"; shift
  local dump
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
  hits="$(found_code "$file" "${NEVER_CODE[@]}" "${GITHUB_CODE[@]}")"
  if [[ "$file" == *.apk ]]; then
    hits+=$'\n'"$(found_permissions "$file" "${NEVER_PERMISSIONS[@]}" "${GITHUB_PERMISSIONS[@]}")"
  fi
  hits="$(sed '/^$/d' <<<"$hits")"
  if [ -n "$hits" ]; then
    echo "::error::$file contains code or permissions the store build must not have:"; echo "$hits" | sed 's/^/  /'
    failed=1
  else
    echo "OK: $file has no update code, notifications or WorkManager"
  fi
done

if [ -n "$github" ]; then
  never="$(found_code "$github" "${NEVER_CODE[@]}")"$'\n'"$(found_permissions "$github" "${NEVER_PERMISSIONS[@]}")"
  never="$(sed '/^$/d' <<<"$never")"
  if [ -n "$never" ]; then
    echo "::error::The GitHub build $github can install apps or update itself:"; echo "$never" | sed 's/^/  /'
    failed=1
  fi
  extras="$(found_code "$github" "${GITHUB_CODE[@]}")"$'\n'"$(found_permissions "$github" "${GITHUB_PERMISSIONS[@]}")"
  for expected in "${GITHUB_PERMISSIONS[@]}" "${GITHUB_CODE[@]}"; do
    if ! grep -qxF "$expected" <<<"$extras"; then
      echo "::error::Check is broken: expected '$expected' in the GitHub build $github"
      failed=1
    fi
  done
  [ "$failed" = 1 ] || echo "OK: $github has no update code, and the same checks find its extras"
fi

exit "$failed"
