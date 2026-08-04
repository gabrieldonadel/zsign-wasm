'use strict';

const fs = require('fs');
const path = require('path');

function chunkString(input, size) {
  const out = [];
  for (let i = 0; i < input.length; i += size) {
    out.push(input.slice(i, i + size));
  }
  return out;
}

function buildBase64Literal(base64) {
  const chunks = chunkString(base64, 120);
  return chunks.map((line) => `  '${line}'`).join(' +\n');
}

function main() {
  const [runtimePath, wasmPath, clientPath, outputPath] = process.argv.slice(2);
  if (!runtimePath || !wasmPath || !clientPath || !outputPath) {
    console.error('Usage: node pack-single.js <runtime.js> <runtime.wasm> <client.js> <output.js>');
    process.exit(1);
  }

  const runtimeJs = fs.readFileSync(runtimePath, 'utf8');
  const clientJs = fs.readFileSync(clientPath, 'utf8');
  const wasmBase64 = fs.readFileSync(wasmPath).toString('base64');
  const wasmLiteral = buildBase64Literal(wasmBase64);

  const output = [
    '\'use strict\';',
    '',
    'const createZsignModule = (() => {',
    '  const __innerModule = { exports: {} };',
    '  const __innerExports = __innerModule.exports;',
    '  let __factory = null;',
    '',
    '  ((module, exports, require, __filename, __dirname, globalThis) => {',
    runtimeJs,
    '',
    '    __factory = typeof module.exports === \'function\'',
    '      ? module.exports',
    '      : (typeof createZsignModule === \'function\' ? createZsignModule : null);',
    '  })(__innerModule, __innerExports, require, __filename, __dirname, globalThis);',
    '',
    '  if (typeof __factory !== \'function\') {',
    '    throw new Error(\'Failed to initialize embedded zsign wasm factory.\');',
    '  }',
    '',
    '  return __factory;',
    '})();',
    '',
    'const EMBEDDED_WASM_BASE64 =',
    `${wasmLiteral};`,
    '',
    'let __cachedWasmBinary = null;',
    '',
    'function decodeBase64ToBytes(base64) {',
    '  if (typeof Buffer !== \'undefined\') {',
    '    return new Uint8Array(Buffer.from(base64, \'base64\'));',
    '  }',
    '',
    '  if (typeof atob === \'function\') {',
    '    const decoded = atob(base64);',
    '    const bytes = new Uint8Array(decoded.length);',
    '    for (let i = 0; i < decoded.length; i += 1) {',
    '      bytes[i] = decoded.charCodeAt(i);',
    '    }',
    '    return bytes;',
    '  }',
    '',
    '  throw new Error(\'No base64 decoder available.\');',
    '}',
    '',
    'function getEmbeddedWasmBinary() {',
    '  if (!__cachedWasmBinary) {',
    '    __cachedWasmBinary = decodeBase64ToBytes(EMBEDDED_WASM_BASE64);',
    '  }',
    '  return __cachedWasmBinary;',
    '}',
    '',
    'function createEmbeddedZsignModule(moduleOptions = {}) {',
    '  const options = { ...moduleOptions };',
    '  if (!options.wasmBinary) {',
    '    options.wasmBinary = getEmbeddedWasmBinary();',
    '  }',
    '  return createZsignModule(options);',
    '}',
    '',
    'const ZsignWasmClient = (() => {',
    '  const __clientModule = { exports: {} };',
    '  const __clientExports = __clientModule.exports;',
    '',
    '  ((module, exports, require, __filename, __dirname) => {',
    clientJs,
    '  })(__clientModule, __clientExports, require, __filename, __dirname);',
    '',
    '  const exported = __clientModule.exports || {};',
    '  if (!exported.ZsignWasmClient) {',
    '    throw new Error(\'Failed to initialize embedded ZsignWasmClient.\');',
    '  }',
    '',
    '  return exported.ZsignWasmClient;',
    '})();',
    '',
    'const __originalCreate = ZsignWasmClient.create.bind(ZsignWasmClient);',
    'ZsignWasmClient.create = function create(options = {}) {',
    '  const merged = { ...options };',
    '  if (!merged.moduleFactory && !merged.moduleFactoryPath) {',
    '    merged.moduleFactory = createEmbeddedZsignModule;',
    '  }',
    '  return __originalCreate(merged);',
    '};',
    '',
    'module.exports = {',
    '  createZsignModule,',
    '  createEmbeddedZsignModule,',
    '  ZsignWasmClient',
    '};',
    ''
  ].join('\n');

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, output, 'utf8');

  // The package root is "type": "module", which would make Node parse the
  // CommonJS bundles in this directory as ESM (and silently drop their
  // exports). Scope the directory back to CommonJS so require() works.
  fs.writeFileSync(
    path.join(path.dirname(outputPath), 'package.json'),
    JSON.stringify({ type: 'commonjs' }, null, 2) + '\n',
    'utf8'
  );
}

main();
