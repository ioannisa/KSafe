#!/usr/bin/env bash
# Runs the :android-shrink-test probe on a connected device or emulator and fails unless every run
# passes, the R8 builds and the unminified builds read each other's data, and both report the same
# facts about the device.
#
#   .github/scripts/android-shrink-probe.sh <apk-dir> <out-dir> <expected-ksafe-version>
#
# <apk-dir> holds full-release.apk, full-unminified.apk, bare-release.apk and bare-unminified.apk,
# and optionally full-compat.apk and bare-compat.apk (the releases built with
# -Pandroid.enableR8.fullMode=false).
# ANDROID_SERIAL picks the device. Only the probe app is installed, and it is removed at the end.
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 <apk-dir> <out-dir> <expected-ksafe-version>" >&2
  exit 2
fi
APKS=$1
OUT=$2
VERSION=$3
PKG=eu.anifantakis.ksafe.shrinktest.android
mkdir -p "$OUT"

fail() {
  echo "::error::$*" >&2
  exit 1
}

uninstall() {
  adb uninstall "$PKG" > /dev/null 2>&1 || true
}
trap uninstall EXIT

# macOS has no `timeout`; there the run just has no time limit.
limit() {
  if command -v timeout > /dev/null; then timeout "$@"; else shift; "$@"; fi
}

# probe <apk> <write|read> <label> <expected build.minified>
probe() {
  local apk=$1 phase=$2 label=$3 minified=$4
  local log="$OUT/$label.txt"
  [ -f "$apk" ] || fail "$apk is missing"
  echo "== $label ($(basename "$apk"), $phase)"
  adb install -r "$apk" > /dev/null
  # Each run starts a fresh process, so a read phase reads from disk.
  limit 300 adb shell am instrument -w -e phase "$phase" -e expectedVersion "$VERSION" \
    "$PKG/$PKG.ShrinkProbe" | tr -d '\r' > "$log" || true
  if ! grep -qx 'INSTRUMENTATION_RESULT: probe=PASS' "$log" || ! grep -qx 'INSTRUMENTATION_CODE: -1' "$log"; then
    cat "$log"
    adb logcat -d -t 3000 > "$OUT/$label.logcat.txt" 2>&1 || true
    fail "shrink probe run $label failed"
  fi
  if ! grep -qx "INSTRUMENTATION_RESULT: build.minified=$minified" "$log"; then
    cat "$log"
    fail "$label: expected build.minified=$minified; was the APK built as intended?"
  fi
  if [ "$minified" = true ] && grep -qx 'INSTRUMENTATION_RESULT: build.ksafeClass=eu.anifantakis.lib.ksafe.KSafe' "$log"; then
    cat "$log"
    fail "$label: R8 kept the name of KSafe's own class; does a shipped rule keep all of KSafe?"
  fi
  grep '^INSTRUMENTATION_RESULT: fact\.' "$log" > "$OUT/$label.facts" || fail "$label reported no facts"
  grep '^INSTRUMENTATION_RESULT: link\.' "$log" > "$OUT/$label.links" || fail "$label reported no links"
}

# same <kind> <label> <label>: the two runs must report identical facts or links.
same() {
  local kind=$1 a=$2 b=$3
  if ! diff -u "$OUT/$a.$kind" "$OUT/$b.$kind"; then
    fail "$a and $b report different $kind"
  fi
}

# pair <flavor label> <unminified apk> <minified apk>: each build reads what the other wrote.
pair() {
  local label=$1 plain=$2 shrunk=$3
  uninstall
  probe "$plain" write "$label-unminified-write" false
  probe "$shrunk" read "$label-minified-read" true
  same links "$label-unminified-write" "$label-minified-read"

  uninstall
  probe "$shrunk" write "$label-minified-write" true
  probe "$plain" read "$label-unminified-read" false
  same links "$label-minified-write" "$label-unminified-read"

  same facts "$label-unminified-write" "$label-minified-write"
  same facts "$label-unminified-read" "$label-minified-read"
  echo "== $label: passed, $(wc -l < "$OUT/$label-minified-read.facts" | tr -d ' ') facts identical with and without R8"
}

# compat <flavor>: the same pairing for <flavor>-compat.apk, if the folder has one.
compat() {
  local flavor=$1
  [ -f "$APKS/$flavor-compat.apk" ] || return 0
  if cmp -s "$APKS/$flavor-compat.apk" "$APKS/$flavor-release.apk"; then
    fail "$flavor-compat.apk is the same file as $flavor-release.apk; R8 compat mode did not take effect"
  fi
  pair "$flavor-compat" "$APKS/$flavor-unminified.apk" "$APKS/$flavor-compat.apk"
}

pair full "$APKS/full-unminified.apk" "$APKS/full-release.apk"
compat full
pair bare "$APKS/bare-unminified.apk" "$APKS/bare-release.apk"
compat bare

echo "== Facts reported by the minified full build:"
sed 's/^INSTRUMENTATION_RESULT: //' "$OUT/full-minified-read.facts"
