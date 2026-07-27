#!/usr/bin/env bash
# Runs the FULL existing Kotlin test suite (commonTest + iosTest, ~185 tests) on a connected
# iPhone. The suite is kotlin.test (not XCTest), so we build the Kotlin/Native iosArm64 test
# binary, wrap it in a signed .app, and launch it via devicectl, capturing the runner output.
#
# Prereq: run ./run-xctest.sh once first so Xcode has generated a provisioning profile for
# "$BUNDLE_ID.host" (this script reuses it).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
source "$HERE/common.sh"
BUILD="$HERE/build"; APP="$BUILD/KSafeTests.app"; mkdir -p "$BUILD"

echo ">> building iosArm64 test binary"
(cd "$REPO" && ./gradlew :ksafe:linkDebugTestIosArm64 -q)
[ -f "$KEXE" ] || { echo "test.kexe not found: $KEXE" >&2; exit 1; }

echo ">> locating a provisioning profile for $BUNDLE_ID.host"
PROFILE=""
for p in "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles/"*.mobileprovision; do
  [ -f "$p" ] || continue
  if security cms -D -i "$p" 2>/dev/null | grep -q "$BUNDLE_ID.host"; then PROFILE="$p"; break; fi
done
[ -n "$PROFILE" ] || { echo "No profile for $BUNDLE_ID.host — run ./run-xctest.sh once first." >&2; exit 1; }

echo ">> assembling + signing $APP"
rm -rf "$APP"; mkdir -p "$APP"
cp "$KEXE" "$APP/KSafeTests"
cp "$HERE/Info.plist" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID.host" "$APP/Info.plist"
cp "$PROFILE" "$APP/embedded.mobileprovision"
security cms -D -i "$PROFILE" > "$BUILD/profile.plist"
/usr/libexec/PlistBuddy -x -c "Print :Entitlements" "$BUILD/profile.plist" > "$BUILD/ent.plist"
codesign -f -s "${SIGN_ID:?no valid signing identity}" --entitlements "$BUILD/ent.plist" --timestamp=none "$APP"

echo ">> installing on device"
xcrun devicectl device install app --device "$UDID" "$APP" >/dev/null

echo ">> running FULL kotlin.test suite on device"
# NOTE: a few iosTest cases assert the SIMULATOR/no-entitlement behaviour (Keychain THROWS).
# On a real signed device the Keychain WORKS, so those assert-failure tests report as failures
# — that is correct device behaviour, not a bug. See README.
xcrun devicectl device process launch --console --terminate-existing --device "$UDID" "$BUNDLE_ID.host"
