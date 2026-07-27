#!/usr/bin/env bash
# Runs the curated Swift XCTest cases (Tests/KSafeDeviceTests.swift) on a connected iPhone,
# exercising the KSafe Apple engine on REAL Secure Enclave + Keychain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
source "$HERE/common.sh"

echo ">> building iosArm64 framework"
(cd "$REPO" && ./gradlew :ksafe:linkDebugFrameworkIosArm64 -q)

echo ">> generating Xcode project"
export DEVELOPMENT_TEAM="$TEAM" KSAFE_FRAMEWORK="$KSAFE_FW" BUNDLE_ID="$BUNDLE_ID"
(cd "$HERE/xcode" && rm -rf KSafeDeviceTest.xcodeproj && ruby gen.rb)

echo ">> running curated Swift XCTest on device"
xcodebuild -project "$HERE/xcode/KSafeDeviceTest.xcodeproj" -scheme KSafeDeviceTests \
  -destination "platform=iOS,id=$UDID" -allowProvisioningUpdates -parallel-testing-enabled NO test
