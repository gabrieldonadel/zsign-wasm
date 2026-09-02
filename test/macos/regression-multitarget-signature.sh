#!/bin/bash
# Regression test for signing an app that contains an app extension, via the
# multi-profile path. It guards two defects that reached production:
#   1. The extension must be signed with its OWN entitlements (application-identifier
#      = TEAMID.<extension bundle id>), not the parent app's, or App Store validation
#      rejects it (altool 90046/90164).
#   2. Each bundle's embedded.mobileprovision must be written BEFORE its CodeResources
#      seal is computed, or codesign reports "a sealed resource is missing or invalid"
#      (altool 90034) when the profile changes during a repack.
#
# Uses a synthetic identity + profiles whose issuer DN matches Apple WWDR CA G3.
# codesign trust evaluation fails (synthetic CA); the test only asserts the seal is
# valid and the per-target entitlements are correct.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MODULE="$ROOT/binary/zsign-wasm.js"
JSZIP="$ROOT/node_modules/jszip"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo -e "\033[31mFAIL:\033[0m $1"; exit 1; }
ok()   { echo -e "\033[32mOK:\033[0m $1"; }

command -v node >/dev/null 2>&1 || { echo "node not found; skipping."; exit 0; }
command -v codesign >/dev/null 2>&1 || { echo "codesign not found (not macOS); skipping."; exit 0; }
[[ -f "$MODULE" ]] || fail "missing $MODULE (build first: cd build/wasm && make bundle)"
[[ -d "$JSZIP" ]] || fail "missing jszip ($JSZIP); run the package manager install first"

TEAM=TEST00TEAM
APP_ID=com.test.app
EXT_ID=com.test.app.NotificationService

# --- synthetic identity: CA subject == Apple WWDR CA G3 DN ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -days 3650 \
  -subj "/CN=Apple Worldwide Developer Relations Certification Authority/OU=G3/O=Apple Inc./C=US" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/leaf.key" -out "$WORK/leaf.csr" \
  -subj "/UID=$TEAM/CN=Apple Distribution: Test User ($TEAM)/OU=$TEAM/O=Test User/C=US" >/dev/null 2>&1
openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
  -out "$WORK/leaf.crt" -days 825 >/dev/null 2>&1
openssl pkcs12 -export -inkey "$WORK/leaf.key" -in "$WORK/leaf.crt" -out "$WORK/leaf.p12" -passout pass: >/dev/null 2>&1

# --- a CMS-signed provisioning profile for a given bundle id ---
make_profile() {
  local bundle_id="$1" out="$2"
  cat > "$WORK/prov.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>TeamIdentifier</key><array><string>$TEAM</string></array>
<key>Entitlements</key><dict>
<key>application-identifier</key><string>$TEAM.$bundle_id</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM</string>
<key>get-task-allow</key><false/>
</dict></dict></plist>
PLIST
  openssl cms -sign -signer "$WORK/leaf.crt" -inkey "$WORK/leaf.key" -in "$WORK/prov.plist" \
    -outform DER -nodetach -out "$out" >/dev/null 2>&1
}
make_profile "$APP_ID" "$WORK/app.mobileprovision"
make_profile "$EXT_ID" "$WORK/ext.mobileprovision"

# --- minimal app bundle with a nested extension ---
APP="$WORK/Payload/Test.app"
EXT="$APP/PlugIns/NotificationService.appex"
mkdir -p "$APP" "$EXT"
thin() { lipo /bin/ls -thin arm64e -output "$1" 2>/dev/null || lipo /bin/ls -thin arm64 -output "$1" 2>/dev/null || cp /bin/ls "$1"; }
thin "$APP/Test"
thin "$EXT/NotificationService"
info_plist() {
  local id="$1" exe="$2" pkg="$3" out="$4"
  cat > "$WORK/info.xml" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$id</string>
<key>CFBundleExecutable</key><string>$exe</string>
<key>CFBundlePackageType</key><string>$pkg</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
  plutil -convert binary1 -o "$out" "$WORK/info.xml"
}
info_plist "$APP_ID" Test APPL "$APP/Info.plist"
info_plist "$EXT_ID" NotificationService "XPC!" "$EXT/Info.plist"
# Pre-place a stale profile in the extension so the test exercises a profile CHANGE
# during signing (the scenario that broke the seal in production).
cp "$WORK/app.mobileprovision" "$EXT/embedded.mobileprovision"

(cd "$WORK" && zip -qry app.ipa Payload)

# --- sign the whole bundle via the multi-profile path ---
node - "$MODULE" "$JSZIP" "$WORK/app.ipa" "$WORK/signed.ipa" "$WORK/leaf.crt" "$WORK/leaf.p12" \
  "$WORK/app.mobileprovision" "$WORK/ext.mobileprovision" <<'NODE'
const fs = require('fs');
const [modulePath, jszipPath, inIpa, outIpa, cert, p12, ...provs] = process.argv.slice(2);
const createZsignModule = require(modulePath);
const JSZip = require(jszipPath);
const norm = (p) => p.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
createZsignModule().then(async (mod) => {
  const M = mod.FS;
  const root = '/work/input', assets = '/work/assets';
  M.mkdirTree(root); M.mkdirTree(assets);
  const zip = await JSZip.loadAsync(fs.readFileSync(inIpa));
  for (const [name, entry] of Object.entries(zip.files)) {
    const clean = norm(name); if (!clean) continue;
    const out = `${root}/${clean}`;
    if (entry.dir) { M.mkdirTree(out); continue; }
    const data = await entry.async('uint8array');
    const s = out.lastIndexOf('/'); if (s > 0) M.mkdirTree(out.slice(0, s));
    M.writeFile(out, data, { canOwn: true });
  }
  const put = (n, b) => { const p = `${assets}/${n}`; M.writeFile(p, new Uint8Array(b), { canOwn: true }); return p; };
  const certFile = put('cert.bin', fs.readFileSync(cert));
  const pkeyFile = put('pkey.bin', fs.readFileSync(p12));
  const provFiles = provs.map((p, i) => put(`p${i}.mobileprovision`, fs.readFileSync(p)));

  // ZsignWasmClient lives beside the module in binary/.
  const path = require('path');
  const { ZsignWasmClient } = require(path.join(path.dirname(modulePath), 'ZsignWasmClient.js'));
  const client = new ZsignWasmClient(mod);
  client.signBundleMulti(root, { certFile, pkeyFile, provFiles, password: '' });

  const outZip = new JSZip();
  (function walk(d) {
    for (const n of M.readdir(d)) {
      if (n === '.' || n === '..') continue;
      const p = `${d}/${n}`; const st = M.stat(p);
      if (M.isDir(st.mode)) walk(p);
      else outZip.file(p.slice(root.length + 1), M.readFile(p, { encoding: 'binary' }));
    }
  })(root);
  fs.writeFileSync(outIpa, Buffer.from(await outZip.generateAsync({ type: 'uint8array' })));
}).catch((e) => { console.error(e); process.exit(1); });
NODE
[[ -f "$WORK/signed.ipa" ]] || fail "signing failed"
ok "signed app + extension via the multi-profile path"

rm -rf "$WORK/out"; mkdir "$WORK/out"; unzip -q "$WORK/signed.ipa" -d "$WORK/out"
SIGNED_APP="$WORK/out/Payload/Test.app"
SIGNED_EXT="$SIGNED_APP/PlugIns/NotificationService.appex"

# Assert a bundle's on-disk embedded.mobileprovision is the one recorded in its
# CodeResources seal. If the profile is written after the seal is computed (the
# ordering bug) these differ, even though `codesign --verify` may not flag it on a
# minimal bundle, so compare the hashes directly.
seal_covers_profile() {
  python3 - "$1" <<'PY'
import sys, hashlib, plistlib
bundle = sys.argv[1]
prov = open(f"{bundle}/embedded.mobileprovision", "rb").read()
cr = plistlib.load(open(f"{bundle}/_CodeSignature/CodeResources", "rb"))
entry = cr.get("files2", {}).get("embedded.mobileprovision")
sealed = entry.get("hash") if isinstance(entry, dict) else None
if sealed is None:
    f = cr.get("files", {}).get("embedded.mobileprovision")
    sealed = f.get("hash") if isinstance(f, dict) else f
sys.exit(0 if sealed == hashlib.sha1(prov).digest() else 1)
PY
}

# 1. The extension's provisioning profile must be inside its CodeResources seal.
seal_covers_profile "$SIGNED_EXT" || fail "extension embedded.mobileprovision is not covered by its CodeResources seal (ordering regression)"
ok "extension profile is sealed in its CodeResources"

# 2. The extension must be sealed with ITS OWN provisioning profile (matched by bundle id).
EXT_PROFILE_APPID="$(security cms -D -i "$SIGNED_EXT/embedded.mobileprovision" 2>/dev/null | plutil -extract Entitlements.application-identifier raw - 2>/dev/null)"
[[ "$EXT_PROFILE_APPID" == "$TEAM.$EXT_ID" ]] || fail "extension embedded profile is for '$EXT_PROFILE_APPID', expected '$TEAM.$EXT_ID'"
ok "extension carries its own provisioning profile ($EXT_PROFILE_APPID)"

# 3. The app's own profile must likewise be sealed.
seal_covers_profile "$SIGNED_APP" || fail "app embedded.mobileprovision is not covered by its CodeResources seal"
ok "app profile is sealed in its CodeResources"

echo -e "\033[32mALL CHECKS PASSED\033[0m"
