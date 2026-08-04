import type {
  SignMachOOptions,
  SignIpaOptions
} from "./runtime.js";

import {
  ZsignWasmResigner,
  ZsignWasmClient,
  createEmbeddedZsignModule,
  createZsignModule
} from "./runtime.js";

export interface CreateResignerOptions {
  moduleFactory?: (opts?: Record<string, unknown>) => Promise<unknown>;
  moduleOptions?: Record<string, unknown>;
}

export interface CreateClientOptions {
  moduleFactory?: (opts?: Record<string, unknown>) => Promise<unknown>;
  moduleOptions?: Record<string, unknown>;
}

export interface MachOSignResult {
  data: Uint8Array;
}

export interface IpaSignResult {
  data: Uint8Array;
}

export class ZsignClient {
  private client: ZsignWasmClient | ZsignWasmResigner | null = null;
  private initialized = false;

  private constructor() {}

  static async create(options: CreateClientOptions = {}): Promise<ZsignClient> {
    const instance = new ZsignClient();
    instance.client = await ZsignWasmClient.create(options);
    instance.initialized = true;
    return instance;
  }

  private ensureInitialized(): void {
    if (!this.initialized || !this.client) {
      throw new Error('ZsignClient is not initialized. Call create() first.');
    }
  }

  version(): string {
    this.ensureInitialized();
    return this.client!.version();
  }

  setLogLevel(level: number): number {
    this.ensureInitialized();
    return this.client!.setLogLevel(level);
  }

  signMachO(inputMachO: Uint8Array | ArrayBuffer | Buffer, options: SignMachOOptions = {}): MachOSignResult {
    this.ensureInitialized();
    const data = this.client!.signMachO(inputMachO, options);
    return { data };
  }
}

export class ZsignResigner {
  private resigner: ZsignWasmResigner | null = null;
  private initialized = false;

  private constructor() {}

  static async create(options: CreateResignerOptions = {}): Promise<ZsignResigner> {
    const instance = new ZsignResigner();
    instance.resigner = await ZsignWasmResigner.create(options);
    instance.initialized = true;
    return instance;
  }

  private ensureInitialized(): void {
    if (!this.initialized || !this.resigner) {
      throw new Error('ZsignResigner is not initialized. Call create() first.');
    }
  }

  version(): string {
    this.ensureInitialized();
    return this.resigner!.version();
  }

  setLogLevel(level: number): number {
    this.ensureInitialized();
    return this.resigner!.setLogLevel(level);
  }

  signMachO(inputMachO: Uint8Array | ArrayBuffer | Buffer, options: SignMachOOptions = {}): MachOSignResult {
    this.ensureInitialized();
    const data = this.resigner!.signMachO(inputMachO, options);
    return { data };
  }

  async signIpa(inputIpa: Uint8Array | ArrayBuffer | Buffer, options: SignIpaOptions = {}): Promise<IpaSignResult> {
    this.ensureInitialized();
    const data = await this.resigner!.signIpa(inputIpa, options);
    return { data };
  }
}

export async function createClient(options?: CreateClientOptions): Promise<ZsignClient> {
  return ZsignClient.create(options);
}

export async function createResigner(options?: CreateResignerOptions): Promise<ZsignResigner> {
  return ZsignResigner.create(options);
}

export type {
  SignMachOOptions,
  SignIpaOptions,
  SignBundleOptions,
  SignBundleMultiOptions,
  EmscriptenFs,
  EmscriptenModuleLike,
  ZsignWasmClientInstance,
  WasmBundleExports
} from "./runtime.js";

export {
  ZsignWasmClient,
  ZsignWasmResigner,
  createEmbeddedZsignModule,
  createZsignModule
} from "./runtime.js";

// Export certificate chain utilities
export {
  CertificateChainBuilder,
  certChainBuilder,
  buildCertificateChain,
  buildCertificateChainDER
} from "./certchain.js";

export type {
  CertificateChainOptions,
  P12ChainOptions
} from "./certchain.js";
