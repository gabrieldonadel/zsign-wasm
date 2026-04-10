const { ZsignWasmClient } = require('../binary/zsign-wasm.min.js');
const fs = require('fs');
(async () => {
    const client = await ZsignWasmClient.create();
    const inputMacho = fs.readFileSync("./test/dylib/bin/demo1.dylib");
    const cert = fs.readFileSync("./test/assets/generated/local_test.cer");
    const key = fs.readFileSync("./test/assets/generated/local_test.key");
    const signedMacho = await client.signMacho(inputMacho, cert, key);
    fs.writeFileSync("./test/dylib/bin/demo1-signed.dylib", Buffer.from(signedMacho));
})()
