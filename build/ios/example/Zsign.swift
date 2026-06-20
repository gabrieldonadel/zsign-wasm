// Example thin Swift wrapper around the zsign C ABI.
//
// Drop this into an app target that links zsign.xcframework. The framework
// exposes the C functions through the `Zsign` Clang module (see module.modulemap),
// so `import Zsign` makes them available directly.

import Foundation
import Zsign

public enum ZsignError: Error {
    case signingFailed(code: Int32)
}

public struct Zsign {

    /// Returns the underlying zsign version string (e.g. "0.7").
    public static var version: String {
        String(cString: zsign_version())
    }

    /// Point zsign at a writable temp directory. The default already resolves to
    /// the app sandbox via $TMPDIR, so calling this is optional.
    public static func setTempRoot(_ path: String) {
        zsign_set_temp_root(path)
    }

    /// Sign a Mach-O image entirely in memory.
    ///
    /// - Parameters:
    ///   - macho: the raw Mach-O (dylib/executable) bytes.
    ///   - cert / pkey / prov: DER/PEM/p12 and .mobileprovision bytes. Omit for ad-hoc.
    ///   - password: p12/private-key password, if any.
    ///   - entitlements: optional entitlements plist bytes.
    ///   - adhoc: ad-hoc signature only (no identity required).
    ///   - sha256Only: emit a single SHA256 code directory.
    ///   - forceSign: re-sign even if already signed.
    /// - Returns: the signed Mach-O bytes.
    public static func signMachO(
        _ macho: Data,
        cert: Data? = nil,
        pkey: Data? = nil,
        prov: Data? = nil,
        password: String? = nil,
        entitlements: Data? = nil,
        adhoc: Bool = false,
        sha256Only: Bool = false,
        forceSign: Bool = true
    ) throws -> Data {

        // Helper that exposes an optional Data as (ptr, len) to a closure.
        func withBytes<R>(_ data: Data?, _ body: (UnsafePointer<UInt8>?, UInt32) -> R) -> R {
            guard let data, !data.isEmpty else { return body(nil, 0) }
            return data.withUnsafeBytes { raw in
                body(raw.bindMemory(to: UInt8.self).baseAddress, UInt32(data.count))
            }
        }

        var outData: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt32 = 0

        let rc: Int32 = withBytes(macho) { mPtr, mLen in
            withBytes(cert) { cPtr, cLen in
                withBytes(pkey) { kPtr, kLen in
                    withBytes(prov) { pPtr, pLen in
                        withBytes(entitlements) { ePtr, eLen in
                            zsign_sign_macho_mem(
                                mPtr, mLen,
                                cPtr, cLen,
                                kPtr, kLen,
                                pPtr, pLen,
                                password,
                                ePtr, eLen,
                                adhoc ? 1 : 0,
                                sha256Only ? 1 : 0,
                                forceSign ? 1 : 0,
                                &outData, &outLen)
                        }
                    }
                }
            }
        }

        guard rc == 0, let outData else {
            throw ZsignError.signingFailed(code: rc)
        }
        defer { zsign_free_buffer(outData) }
        return Data(bytes: outData, count: Int(outLen))
    }
}
