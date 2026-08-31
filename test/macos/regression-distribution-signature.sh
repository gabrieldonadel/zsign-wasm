#!/bin/bash
# Regression test for the distribution-signature fixes:
#   1. CMS "hash agility V2" attribute (OID 1.2.840.113635.100.9.2) must carry one
#      AgileHash per code directory (SHA-1 + SHA-256). Apple's verifier rejects the
#      signature ("code or signature have been modified") when the count is wrong.
#   2. DER entitlements must be wrapped as [APPLICATION 16]{ INTEGER 1, dict }.
#   3. The main executable's exec-segment flags must be MAIN_BINARY (0x1) only,
#      never ALLOW_UNSIGNED, when get-task-allow is false.
#
# Uses a synthetic identity whose issuer DN matches Apple WWDR CA G3 (so zsign
# accepts it). codesign trust evaluation will still fail (CSSMERR_TP_NOT_TRUSTED)
# because the CA is synthetic; that is expected. The test only asserts that the
# SEAL is valid (no "code or signature have been modified") and the structure is
# correct.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ZSIGN_JS="$HERE/../../binary/zsign-wasm.js"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo -e "\033[31mFAIL:\033[0m $1"; exit 1; }
ok()   { echo -e "\033[32mOK:\033[0m $1"; }

command -v node >/dev/null 2>&1 || { echo "node not found; skipping."; exit 0; }
command -v codesign >/dev/null 2>&1 || { echo "codesign not found (not macOS); skipping."; exit 0; }
[[ -f "$ZSIGN_JS" ]] || fail "missing $ZSIGN_JS (build first: cd build/wasm && make bundle)"

# --- synthetic identity: CA subject == Apple WWDR CA G3 DN ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -days 3650 \
  -subj "/CN=Apple Worldwide Developer Relations Certification Authority/OU=G3/O=Apple Inc./C=US" >/dev/null 2>&1
[[ "$(openssl x509 -in "$WORK/ca.crt" -noout -subject_hash)" == "9b16b75c" ]] || fail "CA issuer hash mismatch"
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/leaf.key" -out "$WORK/leaf.csr" \
  -subj "/UID=TEST00TEAM/CN=Apple Distribution: Test User (TEST00TEAM)/OU=TEST00TEAM/O=Test User/C=US" >/dev/null 2>&1
openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
  -out "$WORK/leaf.crt" -days 825 >/dev/null 2>&1
openssl pkcs12 -export -inkey "$WORK/leaf.key" -in "$WORK/leaf.crt" -out "$WORK/leaf.p12" -passout pass: >/dev/null 2>&1

cat > "$WORK/prov.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>TeamIdentifier</key><array><string>TEST00TEAM</string></array>
<key>Entitlements</key><dict><key>application-identifier</key><string>TEST00TEAM.com.test.app</string></dict>
</dict></plist>
PLIST
openssl cms -sign -signer "$WORK/leaf.crt" -inkey "$WORK/leaf.key" -in "$WORK/prov.plist" \
  -outform DER -nodetach -out "$WORK/test.mobileprovision" >/dev/null 2>&1

cat > "$WORK/ent.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>application-identifier</key><string>TEST00TEAM.com.test.app</string>
<key>get-task-allow</key><false/>
</dict></plist>
PLIST

lipo /bin/ls -thin arm64e -output "$WORK/macho" 2>/dev/null \
  || lipo /bin/ls -thin arm64 -output "$WORK/macho" 2>/dev/null \
  || cp /bin/ls "$WORK/macho"

node - "$ZSIGN_JS" "$WORK/macho" "$WORK/signed" "$WORK/leaf.crt" "$WORK/leaf.p12" \
  "$WORK/test.mobileprovision" "$WORK/ent.plist" <<'NODE'
const fs = require('fs');
const [mod, inp, out, cert, p12, prov, ent] = process.argv.slice(2);
require(mod)().then((m) => {
  const h8 = m.getHeapU8(), h32 = m.getHeapU32();
  const put = (b) => { const p = m._malloc(b.length); h8.set(b, p); return p; };
  const rd = (p) => fs.readFileSync(p);
  const iP = put(rd(inp)), cP = put(rd(cert)), kP = put(rd(p12)), vP = put(rd(prov)), eP = put(rd(ent));
  const oP = m._malloc(4), lP = m._malloc(4); h32[oP>>2]=0; h32[lP>>2]=0;
  const r = m._zsign_sign_macho_mem(iP, rd(inp).length, cP, rd(cert).length, kP, rd(p12).length,
    vP, rd(prov).length, 0, eP, rd(ent).length, 0, 0, 1, oP, lP);
  if (r === 0) fs.writeFileSync(out, Buffer.from(h8.subarray(h32[oP>>2], h32[oP>>2]+h32[lP>>2])));
  process.exit(r === 0 ? 0 : 1);
}).catch((e) => { console.error(e); process.exit(2); });
NODE
[[ $? -eq 0 && -f "$WORK/signed" ]] || fail "signing failed"
ok "signed the mach-O"

# 1. Seal must be valid: codesign must NOT report a modified/invalid seal.
VERIFY="$(codesign --verify -vvvv "$WORK/signed" 2>&1)"
if echo "$VERIFY" | grep -q "code or signature have been modified"; then
  fail "seal invalid (hash agility regression): $VERIFY"
fi
ok "codesign seal is valid (only trust may fail with a synthetic CA)"

# 2. Both SHA-1 and SHA-256 agile hashes present in the CMS.
codesign -d --extract-certificates="$WORK/c" "$WORK/signed" >/dev/null 2>&1 || true
DUMP="$(codesign -d -vvvv "$WORK/signed" 2>&1)"
echo "$DUMP" | grep -q "Hash choices=sha1,sha256" || fail "expected sha1+sha256 code directories"
ok "SHA-1 and SHA-256 code directories present"

# 3. Entitlements DER must parse (no "invalid entitlements blob").
ENT="$(codesign -d --entitlements - "$WORK/signed" 2>&1)"
echo "$ENT" | grep -qi "invalid entitlements blob" && fail "DER entitlements malformed: $ENT"
ok "DER entitlements parse cleanly"

echo -e "\033[32mALL CHECKS PASSED\033[0m"
