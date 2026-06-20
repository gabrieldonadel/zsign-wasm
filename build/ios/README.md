# zsign for iOS

This builds the zsign signing core as a native iOS static library packaged in an
`.xcframework`, exposing the same C ABI as the wasm build
(`native/zsign_export.h`). The point is to run the signer **natively on-device**
(hardware SHA on ARMv8) instead of through WebAssembly.

The source set mirrors the wasm build: the CLI `main` (`zsign.cpp`) and the
minizip-based `archive.cpp` are excluded. IPA zip/unzip is the host app's job —
exactly as the JS resigner handles it for wasm. The library signs **Mach-O
images** (in-memory, the ideal API for an app) and **extracted bundle folders**.
OpenSSL is the only third-party dependency.

> Scope note: this makes the *signer* run fast natively. iOS still won't
> *install* an arbitrarily re-signed IPA without a valid provisioning profile and
> the usual sideload/MDM/jailbreak constraints — that's orthogonal to signing.

## 1. Get OpenSSL for iOS

You need static `libcrypto.a` / `libssl.a` (plus headers) built for iOS. Any of
these work:

- [OpenSSL-Apple](https://github.com/keeshux/openssl-apple) — produces per-slice
  static libs and an xcframework.
- [OpenSSL-for-iOS](https://github.com/x2on/OpenSSL-for-iOS)
- Your own build via the OpenSSL `Configure ios64-cross` / `iossimulator-*`
  targets.

Arrange them so each slice is a directory containing `include/` and `lib/`:

```
openssl/
  ios-arm64/        # device
    include/openssl/*.h
    lib/{libcrypto.a,libssl.a}
  ios-sim/          # simulator (arm64 + x86_64 fat, or arm64-only on Apple Silicon)
    include/openssl/*.h
    lib/{libcrypto.a,libssl.a}
```

## 2. Build

From this directory:

```bash
make OPENSSL_DEVICE=/abs/path/openssl/ios-arm64 \
     OPENSSL_SIM=/abs/path/openssl/ios-sim
```

Output: `build/ios/dist/zsign.xcframework` (device + simulator slices, OpenSSL
merged in, so the app only links this one artifact).

Options:
- `MIN_IOS=13.0` — minimum deployment target (default `13.0`).
- `OPENSSL_SIM` defaults to `OPENSSL_DEVICE` if you have a single fat/simulator
  archive.
- `make clean` removes `.build/` and `dist/`.

## 3. Integrate

**Xcode:** drag `zsign.xcframework` into your project (Frameworks, Libraries &
Embedded Content). The bundled `module.modulemap` exposes a `Zsign` Clang module.

**Swift Package Manager:** reference it as a binary target:

```swift
.binaryTarget(name: "Zsign", path: "build/ios/dist/zsign.xcframework")
```

## 4. Use

A ready-made Swift wrapper is in [`example/Zsign.swift`](example/Zsign.swift):

```swift
import Zsign

let signed = try Zsign.signMachO(
    machoData,
    cert: certData,           // omit for ad-hoc
    pkey: p12Data,
    prov: mobileprovisionData,
    password: "123456",
    adhoc: false,
    forceSign: true
)
```

Or call the C ABI directly — `zsign_sign_macho_mem`, `zsign_sign_bundle`,
`zsign_set_temp_root`, `zsign_version`, `zsign_set_log_level`,
`zsign_free_buffer` (see `native/zsign_export.h`).

The `*_mem` API writes intermediate files under a temp root that defaults to the
app sandbox (`$TMPDIR/zsign_tmp`). Override with `zsign_set_temp_root()` /
`Zsign.setTempRoot()` if you want a specific location.

## Why native?

The hot path is per-page SHA1/SHA256 hashing of the whole Mach-O (see
`native/signing.cpp`). Native arm64 uses the ARMv8 hardware SHA extensions; the
wasm build uses portable C crypto with no SIMD. Expect the hashing portion to be
~5–10× faster natively and end-to-end signing roughly ~3–6× faster, skewing
higher for larger binaries where hashing dominates.
