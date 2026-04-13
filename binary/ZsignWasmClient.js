'use strict';

const nodeRequire = typeof require === 'function' ? require : null;
const fs = nodeRequire ? nodeRequire('fs') : null;
const path = nodeRequire ? nodeRequire('path') : null;

class ZsignWasmClient {
  static async create(options = {}) {
    const moduleOptions = options.moduleOptions || {};
    let factory = options.moduleFactory;

    if (!factory) {
      const moduleFactoryPath = ZsignWasmClient._resolveModuleFactoryPath(options.moduleFactoryPath);
      // eslint-disable-next-line global-require, import/no-dynamic-require
      const loaded = require(moduleFactoryPath);
      factory = loaded && loaded.default ? loaded.default : loaded;
    }

    if (typeof factory !== 'function') {
      throw new Error('Invalid wasm module factory.');
    }

    const wasmModule = await factory(moduleOptions);
    return new ZsignWasmClient(wasmModule);
  }

  constructor(wasmModule) {
    if (!wasmModule) {
      throw new Error('wasmModule is required.');
    }
    this.mod = wasmModule;
    this._cwrapVersion = this.mod.cwrap('zsign_version', 'string', []);
    this._cwrapSetLogLevel = this.mod.cwrap('zsign_set_log_level', 'number', ['number']);
    this._cwrapSignBundle = this.mod.cwrap('zsign_sign_bundle', 'number', [
      'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string',
      'number', 'number', 'number', 'number', 'number'
    ]);
    this._retCodeMessage = {
      '-204': 'bundle signing failed',
      '-203': 'failed to initialize signing assets',
      '-202': 'non ad-hoc mode requires key and provisioning',
      '-201': 'invalid bundle folder path',
      '-101': 'output pointers are invalid',
      '-102': 'input Mach-O buffer is empty',
      '-103': 'failed to create temporary input file',
      '-104': 'failed to create temporary cert file',
      '-105': 'failed to create temporary private key file',
      '-106': 'failed to create temporary provisioning file',
      '-107': 'failed to create temporary entitlements file',
      '-108': 'failed to read signed output file',
      '-109': 'failed to allocate output buffer',
      '-6': 'signing failed',
      '-5': 'failed to initialize signing assets',
      '-4': 'invalid Mach-O file',
      '-3': 'failed to prepare output file',
      '-2': 'non ad-hoc mode requires key and provisioning',
      '-1': 'invalid input path'
    };
  }

  static _resolveModuleFactoryPath(moduleFactoryPath) {
    if (!path) {
      throw new Error('moduleFactoryPath is required in non-Node runtime.');
    }

    if (moduleFactoryPath) {
      return path.isAbsolute(moduleFactoryPath)
        ? moduleFactoryPath
        : path.resolve(process.cwd(), moduleFactoryPath);
    }

    const candidates = [
      path.resolve(__dirname, './zsign-wasm.js'),
      path.resolve(__dirname, '../../bin/zsign-wasm.js')
    ];

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }

    throw new Error(`Cannot find zsign-wasm.js. Tried: ${candidates.join(', ')}`);
  }

  version() {
    return this._cwrapVersion();
  }

  setLogLevel(level) {
    return this._cwrapSetLogLevel(level | 0);
  }

  signBundle(inputFolder, options = {}) {
    if (!inputFolder || typeof inputFolder !== 'string') {
      throw new TypeError('inputFolder must be a non-empty string.');
    }

    const certFile = typeof options.certFile === 'string' ? options.certFile : '';
    const pkeyFile = typeof options.pkeyFile === 'string' ? options.pkeyFile : '';
    const provFile = typeof options.provFile === 'string' ? options.provFile : '';
    const password = typeof options.password === 'string' ? options.password : '';
    const entitlementsFile = typeof options.entitlementsFile === 'string' ? options.entitlementsFile : '';
    const bundleId = typeof options.bundleId === 'string' ? options.bundleId : '';
    const bundleVersion = typeof options.bundleVersion === 'string' ? options.bundleVersion : '';
    const displayName = typeof options.displayName === 'string' ? options.displayName : '';
    const adhoc = !!options.adhoc;
    const sha256Only = !!options.sha256Only;
    const forceSign = options.forceSign !== undefined ? !!options.forceSign : true;
    const weakInject = !!options.weakInject;
    const enableCache = !!options.enableCache;

    const ret = this._cwrapSignBundle(
      inputFolder,
      certFile,
      pkeyFile,
      provFile,
      password,
      entitlementsFile,
      bundleId,
      bundleVersion,
      displayName,
      adhoc ? 1 : 0,
      sha256Only ? 1 : 0,
      forceSign ? 1 : 0,
      weakInject ? 1 : 0,
      enableCache ? 1 : 0
    );

    if (ret !== 0) {
      const reason = this._retCodeMessage[String(ret)] || 'unknown error';
      throw new Error(`zsign_sign_bundle failed: ${ret} (${reason})`);
    }

    return 0;
  }

  signMacho(inputMachO, options = {}) {
    const inBuf = this._toUint8Array(inputMachO, 'inputMachO');
    const certBuf = this._toOptionalUint8Array(options.cert, 'cert');
    const pkeyBuf = this._toOptionalUint8Array(options.pkey, 'pkey');
    const provBuf = this._toOptionalUint8Array(options.prov, 'prov');
    const entitlementsBuf = this._toOptionalUint8Array(options.entitlements, 'entitlements');
    const password = typeof options.password === 'string' ? options.password : '';

    const adhoc = options.adhoc !== undefined
      ? !!options.adhoc
      : !(pkeyBuf && provBuf);
    const sha256Only = !!options.sha256Only;
    const forceSign = options.forceSign !== undefined ? !!options.forceSign : true;

    const ptrs = [];
    let outPtr = 0;

    try {
      const inPtr = this._allocBytes(inBuf, ptrs);
      const certPtr = certBuf ? this._allocBytes(certBuf, ptrs) : 0;
      const pkeyPtr = pkeyBuf ? this._allocBytes(pkeyBuf, ptrs) : 0;
      const provPtr = provBuf ? this._allocBytes(provBuf, ptrs) : 0;
      const entitlementsPtr = entitlementsBuf ? this._allocBytes(entitlementsBuf, ptrs) : 0;
      const passwdPtr = password ? this._allocCString(password, ptrs) : 0;

      const outPtrPtr = this.mod._malloc(4);
      const outLenPtr = this.mod._malloc(4);
      ptrs.push(outPtrPtr, outLenPtr);

      this.mod.getHeapU32()[outPtrPtr >> 2] = 0;
      this.mod.getHeapU32()[outLenPtr >> 2] = 0;

      const ret = this.mod._zsign_sign_macho_mem(
        inPtr, inBuf.length,
        certPtr, certBuf ? certBuf.length : 0,
        pkeyPtr, pkeyBuf ? pkeyBuf.length : 0,
        provPtr, provBuf ? provBuf.length : 0,
        passwdPtr,
        entitlementsPtr, entitlementsBuf ? entitlementsBuf.length : 0,
        adhoc ? 1 : 0,
        sha256Only ? 1 : 0,
        forceSign ? 1 : 0,
        outPtrPtr,
        outLenPtr
      );

      if (ret !== 0) {
        const reason = this._retCodeMessage[String(ret)] || 'unknown error';
        throw new Error(`zsign_sign_macho_mem failed: ${ret} (${reason})`);
      }

      const heapU32 = this.mod.getHeapU32();
      outPtr = heapU32[outPtrPtr >> 2];
      const outLen = heapU32[outLenPtr >> 2];
      if (!outPtr || !outLen) {
        throw new Error('zsign_sign_macho_mem returned empty output.');
      }

      const heapU8 = this.mod.getHeapU8();
      return heapU8.slice(outPtr, outPtr + outLen);
    } finally {
      if (outPtr) {
        this.mod._zsign_free_buffer(outPtr);
      }
      for (const p of ptrs) {
        if (p) {
          this.mod._free(p);
        }
      }
    }
  }

  signMachoToFile(inputPath, outputPath, options = {}) {
    const fs = this._requireFs();
    const input = fs.readFileSync(inputPath);
    const output = this.signMacho(input, options);
    fs.writeFileSync(outputPath, Buffer.from(output));
    return output.length;
  }

  _requireFs() {
    if (!fs) {
      throw new Error('fs is not available in this runtime.');
    }
    return fs;
  }

  _toOptionalUint8Array(value, name) {
    if (value == null) {
      return null;
    }
    return this._toUint8Array(value, name);
  }

  _toUint8Array(value, name) {
    if (value instanceof Uint8Array) {
      return value;
    }
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    throw new TypeError(`${name} must be Uint8Array, Buffer, or ArrayBuffer.`);
  }

  _allocBytes(bytes, ptrs) {
    const ptr = this.mod._malloc(bytes.length);
    if (!ptr) {
      throw new Error('malloc failed.');
    }
    this.mod.getHeapU8().set(bytes, ptr);
    ptrs.push(ptr);
    return ptr;
  }

  _allocCString(text, ptrs) {
    const len = this.mod.lengthBytesUTF8(text) + 1;
    const ptr = this.mod._malloc(len);
    if (!ptr) {
      throw new Error('malloc failed.');
    }
    this.mod.stringToUTF8(text, ptr, len);
    ptrs.push(ptr);
    return ptr;
  }
}

module.exports = {
  ZsignWasmClient
};
