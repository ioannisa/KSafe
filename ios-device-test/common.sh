# Sourced by run-*.sh. Requires HERE and REPO to be set by the caller.
: "${HERE:?}"; : "${REPO:?}"

TEAM="${DEVELOPMENT_TEAM:-36EL4K6NG5}"          # override: DEVELOPMENT_TEAM=XXXXXXXXXX
BUNDLE_ID="${BUNDLE_ID:-eu.anifantakis.ksafedevtest}"
KSAFE_FW="$REPO/ksafe/build/bin/iosArm64/debugFramework/ksafe.framework"
KEXE="$REPO/ksafe/build/bin/iosArm64/debugTest/test.kexe"

# First VALID (non-revoked) Apple Development/Distribution codesigning identity SHA.
SIGN_ID="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -iE 'Apple (Development|Distribution)' | grep -vi 'REVOKED' | head -1 | awk '{print $2}')"

# Hardware UDID of a connected iPhone (devicectl), overridable via DEVICE_UDID.
detect_udid() {
  local tmp; tmp="$(mktemp)"
  xcrun devicectl list devices --json-output "$tmp" >/dev/null 2>&1 || return
  python3 - "$tmp" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    for x in d.get("result", {}).get("devices", []):
        cp = x.get("connectionProperties", {})
        name = x.get("deviceProperties", {}).get("name", "")
        if "iPhone" in name and cp.get("tunnelState") == "connected":
            print(x.get("hardwareProperties", {}).get("udid", "")); break
except Exception:
    pass
PY
}

UDID="${DEVICE_UDID:-$(detect_udid)}"
if [ -z "$UDID" ]; then
  echo "!! No connected iPhone detected. Connect + unlock + trust the device, then set" >&2
  echo "   DEVICE_UDID=<hardware-udid>  (from: xcrun devicectl list devices)  and retry." >&2
  exit 1
fi
echo ">> device: $UDID   team: $TEAM   signId: ${SIGN_ID:-<none>}"
