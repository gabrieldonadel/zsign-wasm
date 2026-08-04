import JSZip from "jszip";

export interface SignMachOOptions {
  cert?: Uint8Array | ArrayBuffer;
  pkey?: Uint8Array | ArrayBuffer;
  prov?: Uint8Array | ArrayBuffer;
  entitlements?: Uint8Array | ArrayBuffer;
  password?: string;
  adhoc?: boolean;
  sha256Only?: boolean;
  forceSign?: boolean;
}

export interface SignIpaOptions extends SignMachOOptions {
  bundleId?: string;
  bundleVersion?: string;
  displayName?: string;
  weakInject?: boolean;
  enableCache?: boolean;
  zipLevel?: number;
}

type ModuleFactory = (opts?: Record<string, unknown>) => Promise<unknown>;
type BinaryLike = Uint8Array | ArrayBuffer | Buffer;

interface CreateOptions {
  moduleFactory?: ModuleFactory;
  moduleOptions?: Record<string, unknown>;
}

export interface SignBundleOptions {
  certFile?: string;
  pkeyFile?: string;
  provFile?: string;
  password?: string;
  entitlementsFile?: string;
  bundleId?: string;
  bundleVersion?: string;
  displayName?: string;
  adhoc?: boolean;
  sha256Only?: boolean;
  forceSign?: boolean;
  weakInject?: boolean;
  enableCache?: boolean;
}

/**
 * Multi-profile bundle signing: one provisioning profile per bundle in the
 * folder (main app + each app extension / watch app). zsign matches each
 * profile to a bundle by its app-id suffix.
 */
export interface SignBundleMultiOptions extends Omit<SignBundleOptions, "provFile"> {
  provFiles: string[];
}

export interface EmscriptenFs {
  mkdirTree(pathname: string): void;
  writeFile(pathname: string, data: Uint8Array, options?: Record<string, unknown>): void;
  readFile(pathname: string, options?: Record<string, unknown>): Uint8Array;
  readdir(pathname: string): string[];
  stat(pathname: string): { mode: number };
  analyzePath(pathname: string): { exists: boolean };
  isDir(mode: number): boolean;
  isFile(mode: number): boolean;
  rmdir(pathname: string): void;
  unlink(pathname: string): void;
}

export interface EmscriptenModuleLike {
  FS?: EmscriptenFs;
}

/** The client instance created by the wasm bundle's `ZsignWasmClient.create()`. */
export interface ZsignWasmClientInstance {
  mod: EmscriptenModuleLike;
  version(): string;
  setLogLevel(level: number): number;
  signMacho(inputMachO: BinaryLike, options?: SignMachOOptions): Uint8Array;
  signBundle(inputFolder: string, options?: SignBundleOptions): number | void;
  signBundleMulti(inputFolder: string, options: SignBundleMultiOptions): number | void;
}

/** The CommonJS exports of `zsign-wasm/binary/zsign-wasm.min.js`. */
export interface WasmBundleExports {
  ZsignWasmClient: {
    create(options?: CreateOptions): Promise<ZsignWasmClientInstance>;
  };
  createZsignModule?: ModuleFactory;
  createEmbeddedZsignModule?: ModuleFactory;
}

const MODULE_URL = new URL(import.meta.url);
const WASM_BUNDLE_URL = new URL("../binary/zsign-wasm.min.js", MODULE_URL);
const IS_NODE = MODULE_URL.protocol === "file:";

let wasmBundlePromise: Promise<WasmBundleExports> | null = null;

function toUint8Array(value: BinaryLike, name: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(value)) {
    const bufferValue = value as Buffer;
    return new Uint8Array(bufferValue.buffer, bufferValue.byteOffset, bufferValue.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  throw new TypeError(`${name} must be Uint8Array, Buffer, or ArrayBuffer.`);
}

function normalizePath(pathname: string): string {
  return String(pathname || "").replace(/\\/g, "/").replace(/^\/+/, "");
}

function resolveBundleExports(input: unknown): WasmBundleExports | null {
  if (input && typeof input === "object" && "default" in input) {
    const nested = resolveBundleExports((input as Record<string, unknown>).default);
    if (nested) {
      return nested;
    }
  }

  if (!input || typeof input !== "object") {
    return null;
  }

  const candidate = input as Partial<WasmBundleExports>;
  if (candidate.ZsignWasmClient && typeof candidate.ZsignWasmClient.create === "function") {
    return candidate as WasmBundleExports;
  }

  return null;
}

/**
 * Emscripten still emits a CommonJS-flavored bundle here, so the browser path
 * keeps the runtime lazy by evaluating the generated file only when needed.
 */
async function loadBrowserBundle(): Promise<WasmBundleExports> {
  try {
    const imported = await import(/* @vite-ignore */ WASM_BUNDLE_URL.href);
    const resolved = resolveBundleExports(imported);
    if (resolved) {
      return resolved;
    }
  } catch {
  }

  const response = await fetch(WASM_BUNDLE_URL.href);
  if (!response.ok) {
    throw new Error(`Failed to fetch wasm bundle: ${response.status} ${response.statusText}`);
  }

  const source = await response.text();
  const cjsModule = { exports: {} as unknown };
  const evaluate = new Function(
    "module",
    "exports",
    "require",
    "__filename",
    "__dirname",
    "globalThis",
    source,
  );
  evaluate(cjsModule, cjsModule.exports, undefined, WASM_BUNDLE_URL.pathname, "", globalThis);

  const resolved = resolveBundleExports(cjsModule.exports);
  if (!resolved) {
    throw new Error("Invalid wasm bundle exports.");
  }
  return resolved;
}

async function loadNodeBundle(): Promise<WasmBundleExports> {
  const [{ createRequire }, { fileURLToPath }] = await Promise.all([
    import("node:module"),
    import("node:url"),
  ]);
  const require = createRequire(import.meta.url);
  const loaded = require(fileURLToPath(WASM_BUNDLE_URL)) as unknown;
  const resolved = resolveBundleExports(loaded);
  if (!resolved) {
    throw new Error("Invalid wasm bundle exports.");
  }
  return resolved;
}

async function getWasmBundle(): Promise<WasmBundleExports> {
  if (!wasmBundlePromise) {
    wasmBundlePromise = IS_NODE ? loadNodeBundle() : loadBrowserBundle();
  }
  return await wasmBundlePromise;
}

export async function createZsignModule(
  opts: Record<string, unknown> = {},
): Promise<unknown> {
  const bundle = await getWasmBundle();
  const factory = bundle.createZsignModule || bundle.createEmbeddedZsignModule;
  if (typeof factory !== "function") {
    throw new Error("Cannot resolve wasm module factory.");
  }
  return factory(opts);
}

export async function createEmbeddedZsignModule(
  opts: Record<string, unknown> = {},
): Promise<unknown> {
  const bundle = await getWasmBundle();
  const factory = bundle.createEmbeddedZsignModule || bundle.createZsignModule;
  if (typeof factory !== "function") {
    throw new Error("Cannot resolve embedded wasm module factory.");
  }
  return factory(opts);
}

export class ZsignWasmClient {
  readonly mod: EmscriptenModuleLike;
  private readonly client: ZsignWasmClientInstance;

  private constructor(client: ZsignWasmClientInstance) {
    this.client = client;
    this.mod = client.mod;
  }

  static async create(options: CreateOptions = {}): Promise<ZsignWasmClient> {
    const bundle = await getWasmBundle();
    const client = await bundle.ZsignWasmClient.create(options);
    return new ZsignWasmClient(client);
  }

  version(): string {
    return this.client.version();
  }

  setLogLevel(level: number): number {
    return this.client.setLogLevel(level);
  }

  signMachO(inputMachO: BinaryLike, options: SignMachOOptions = {}): Uint8Array {
    return this.client.signMacho(inputMachO, options);
  }

  signBundle(inputFolder: string, options: SignBundleOptions = {}): number | void {
    return this.client.signBundle(inputFolder, options);
  }

  signBundleMulti(inputFolder: string, options: SignBundleMultiOptions): number | void {
    return this.client.signBundleMulti(inputFolder, options);
  }
}

export class ZsignWasmResigner {
  readonly mod: EmscriptenModuleLike;
  private readonly client: ZsignWasmClient;
  private readonly fs: EmscriptenFs;

  private constructor(client: ZsignWasmClient) {
    this.client = client;
    this.mod = client.mod;
    if (!client.mod.FS) {
      throw new Error("Emscripten FS is not available.");
    }
    this.fs = client.mod.FS;
  }

  static async create(options: CreateOptions = {}): Promise<ZsignWasmResigner> {
    let moduleFactory = options.moduleFactory;
    if (!moduleFactory) {
      const bundle = await getWasmBundle();
      moduleFactory = bundle.createEmbeddedZsignModule || bundle.createZsignModule;
    }
    if (typeof moduleFactory !== "function") {
      throw new Error("Cannot resolve wasm module factory.");
    }

    const client = await ZsignWasmClient.create({
      moduleFactory,
      moduleOptions: options.moduleOptions || {},
    });
    return new ZsignWasmResigner(client);
  }

  version(): string {
    return this.client.version();
  }

  setLogLevel(level: number): number {
    return this.client.setLogLevel(level);
  }

  signMachO(inputMachO: BinaryLike, options: SignMachOOptions = {}): Uint8Array {
    return this.client.signMachO(inputMachO, options);
  }

  async signIpa(inputIpa: BinaryLike, options: SignIpaOptions = {}): Promise<Uint8Array> {
    const ipaBytes = toUint8Array(inputIpa, "inputIpa");
    const inputZip = await JSZip.loadAsync(ipaBytes);
    const workspace = this.newWorkspacePath();
    const inputRoot = `${workspace}/input`;
    const assetRoot = `${workspace}/assets`;

    this.fs.mkdirTree(inputRoot);
    this.fs.mkdirTree(assetRoot);

    try {
      for (const [entryName, entry] of Object.entries(inputZip.files)) {
        const cleanName = normalizePath(entryName);
        if (!cleanName) {
          continue;
        }

        const outputPath = `${inputRoot}/${cleanName}`;
        if (entry.dir) {
          this.fs.mkdirTree(outputPath);
          continue;
        }

        const data = await entry.async("uint8array");
        this.writeFile(outputPath, data);
      }

      const certFile = this.writeOptionalAsset(assetRoot, "cert.bin", options.cert);
      const pkeyFile = this.writeOptionalAsset(assetRoot, "pkey.bin", options.pkey);
      const provFile = this.writeOptionalAsset(assetRoot, "prov.mobileprovision", options.prov);
      const entitlementsFile = this.writeOptionalAsset(
        assetRoot,
        "entitlements.plist",
        options.entitlements,
      );

      this.client.signBundle(inputRoot, {
        certFile,
        pkeyFile,
        provFile,
        password: typeof options.password === "string" ? options.password : "",
        entitlementsFile,
        bundleId: typeof options.bundleId === "string" ? options.bundleId : "",
        bundleVersion: typeof options.bundleVersion === "string" ? options.bundleVersion : "",
        displayName: typeof options.displayName === "string" ? options.displayName : "",
        adhoc: !!options.adhoc,
        sha256Only: !!options.sha256Only,
        forceSign: options.forceSign !== undefined ? !!options.forceSign : true,
        weakInject: !!options.weakInject,
        enableCache: !!options.enableCache,
      });

      const outputZip = new JSZip();
      this.walkFiles(inputRoot, (absolutePath) => {
        const relativePath = absolutePath.slice(inputRoot.length + 1);
        outputZip.file(relativePath, this.fs.readFile(absolutePath, { encoding: "binary" }));
      });

      return await outputZip.generateAsync({
        type: "uint8array",
        compression: "DEFLATE",
        compressionOptions: {
          level: Number.isInteger(options.zipLevel) ? (options.zipLevel as number) : 9,
        },
      });
    } finally {
      this.removeRecursively(workspace);
    }
  }

  private writeOptionalAsset(
    assetRoot: string,
    filename: string,
    data: BinaryLike | undefined,
  ): string {
    if (data == null) {
      return "";
    }

    const bytes = toUint8Array(data, filename);
    const outputPath = `${assetRoot}/${filename}`;
    this.writeFile(outputPath, bytes);
    return outputPath;
  }

  private writeFile(outputPath: string, data: Uint8Array): void {
    const separatorIndex = outputPath.lastIndexOf("/");
    if (separatorIndex > 0) {
      this.fs.mkdirTree(outputPath.slice(0, separatorIndex));
    }
    this.fs.writeFile(outputPath, data, { canOwn: true });
  }

  private walkFiles(rootPath: string, onFile: (absolutePath: string) => void): void {
    for (const name of this.fs.readdir(rootPath)) {
      if (name === "." || name === "..") {
        continue;
      }

      const absolutePath = `${rootPath}/${name}`;
      const stat = this.fs.stat(absolutePath);
      if (this.fs.isDir(stat.mode)) {
        this.walkFiles(absolutePath, onFile);
      } else if (this.fs.isFile(stat.mode)) {
        onFile(absolutePath);
      }
    }
  }

  private removeRecursively(pathname: string): void {
    const info = this.fs.analyzePath(pathname);
    if (!info.exists) {
      return;
    }

    const stat = this.fs.stat(pathname);
    if (this.fs.isDir(stat.mode)) {
      for (const name of this.fs.readdir(pathname)) {
        if (name === "." || name === "..") {
          continue;
        }
        this.removeRecursively(`${pathname}/${name}`);
      }
      this.fs.rmdir(pathname);
      return;
    }

    this.fs.unlink(pathname);
  }

  private newWorkspacePath(): string {
    const workspace = `/zsign_ws_${Date.now()}_${Math.floor(Math.random() * 1e9)}`;
    this.fs.mkdirTree(workspace);
    return workspace;
  }
}
