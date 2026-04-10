/**
 * Certificate chain utilities for Apple code signing
 * Helps build complete certificate chains (Developer Cert + WWDR + Root CA)
 */

export interface CertificateChainOptions {
  /**
   * Developer certificate (.cer or .pem)
   */
  developerCert: Uint8Array | ArrayBuffer | Buffer;

  /**
   * WWDR certificate (optional, will download if not provided)
   */
  wwdrCert?: Uint8Array | ArrayBuffer | Buffer;

  /**
   * Apple Root CA (optional, will download if not provided)
   */
  rootCert?: Uint8Array | ArrayBuffer | Buffer;

  /**
   * Include Root CA in chain (default: false, usually not needed)
   */
  includeRootCA?: boolean;
}

export interface P12ChainOptions extends CertificateChainOptions {
  /**
   * Private key (PEM or DER format)
   */
  privateKey: Uint8Array | ArrayBuffer | Buffer;

  /**
   * Password for the output P12 (default: empty string)
   */
  password?: string;
}

export class CertificateChainBuilder {
  private wwdrCache: Uint8Array | null = null;
  private rootCache: Uint8Array | null = null;

  /**
   * Download WWDR certificate from Apple
   */
  async downloadWWDR(): Promise<Uint8Array> {
    if (this.wwdrCache) {
      return this.wwdrCache;
    }

    const WWDR_URLS = [
      'https://www.apple.com/certificateauthority/AppleWWDRCAG6.cer',
      'https://www.apple.com/certificateauthority/AppleWWDRCAG5.cer',
      'https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer',
      'https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer',
    ];

    for (const url of WWDR_URLS) {
      try {
        const response = await fetch(url);
        if (!response.ok) {
          continue;
        }
        const buffer = await response.arrayBuffer();
        this.wwdrCache = new Uint8Array(buffer);
        return this.wwdrCache;
      } catch (error) {
        console.warn(`Failed to download WWDR from ${url}:`, error);
        continue;
      }
    }

    throw new Error('Failed to download WWDR certificate from all known URLs');
  }

  /**
   * Download Apple Root CA
   */
  async downloadRootCA(): Promise<Uint8Array> {
    if (this.rootCache) {
      return this.rootCache;
    }

    const ROOT_URL = 'https://www.apple.com/appleca/AppleIncRootCertificate.cer';

    try {
      const response = await fetch(ROOT_URL);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const buffer = await response.arrayBuffer();
      this.rootCache = new Uint8Array(buffer);
      return this.rootCache;
    } catch (error) {
      throw new Error(`Failed to download Apple Root CA: ${error}`);
    }
  }

  /**
   * Convert DER to PEM format
   */
  derToPem(der: Uint8Array, label: string = 'CERTIFICATE'): string {
    const base64 = this.uint8ArrayToBase64(der);
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
  }

  /**
   * Build complete certificate chain in PEM format
   */
  async buildCertificateChain(options: CertificateChainOptions): Promise<string> {
    const {
      developerCert,
      wwdrCert,
      rootCert,
      includeRootCA = false
    } = options;

    // Load certificates
    const wwdr = wwdrCert || await this.downloadWWDR();
    const root = rootCert || (includeRootCA ? await this.downloadRootCA() : null);

    // Convert to PEM format
    const devPem = this.derToPem(this.toUint8Array(developerCert));
    const wwdrPem = this.derToPem(this.toUint8Array(wwdr));

    // Build chain: Developer Cert + WWDR (+ Root CA if requested)
    let chain = devPem + wwdrPem;
    if (root && includeRootCA) {
      chain += this.derToPem(this.toUint8Array(root));
    }

    return chain;
  }

  /**
   * Build certificate chain and return as concatenated DER buffers
   * This is useful for passing directly to zsign
   */
  async buildCertificateChainDER(options: CertificateChainOptions): Promise<Uint8Array> {
    const {
      developerCert,
      wwdrCert,
      rootCert,
      includeRootCA = false
    } = options;

    const devBytes = this.toUint8Array(developerCert);
    const wwdr = wwdrCert || await this.downloadWWDR();
    const wwdrBytes = this.toUint8Array(wwdr);

    if (includeRootCA) {
      const root = rootCert || await this.downloadRootCA();
      const rootBytes = this.toUint8Array(root);

      // Concatenate: Developer + WWDR + Root
      const result = new Uint8Array(devBytes.length + wwdrBytes.length + rootBytes.length);
      result.set(devBytes, 0);
      result.set(wwdrBytes, devBytes.length);
      result.set(rootBytes, devBytes.length + wwdrBytes.length);
      return result;
    } else {
      // Concatenate: Developer + WWDR
      const result = new Uint8Array(devBytes.length + wwdrBytes.length);
      result.set(devBytes, 0);
      result.set(wwdrBytes, devBytes.length);
      return result;
    }
  }

  /**
   * Utility: Convert various buffer types to Uint8Array
   */
  private toUint8Array(input: Uint8Array | ArrayBuffer | Buffer): Uint8Array {
    if (input instanceof Uint8Array) {
      return input;
    }
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(input)) {
      const bufferInput = input as Buffer;
      return new Uint8Array(bufferInput.buffer, bufferInput.byteOffset, bufferInput.byteLength);
    }
    if (input instanceof ArrayBuffer) {
      return new Uint8Array(input);
    }
    throw new TypeError('Input must be Uint8Array, Buffer, or ArrayBuffer');
  }

  /**
   * Utility: Convert Uint8Array to Base64
   */
  private uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    if (typeof btoa !== 'undefined') {
      return btoa(binary);
    }
    // Node.js environment
    return Buffer.from(binary, 'binary').toString('base64');
  }
}

// Export singleton instance
export const certChainBuilder = new CertificateChainBuilder();

// Export convenience functions
export async function buildCertificateChain(options: CertificateChainOptions): Promise<string> {
  return certChainBuilder.buildCertificateChain(options);
}

export async function buildCertificateChainDER(options: CertificateChainOptions): Promise<Uint8Array> {
  return certChainBuilder.buildCertificateChainDER(options);
}