// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

const testDir = dirname(fileURLToPath(import.meta.url));
const modulePath = resolve(process.argv[2]);
const python = process.env.PYTHON ?? "python3";
const generated = spawnSync(
  python,
  [resolve(testDir, "conformance_vector.py")],
  { encoding: "utf8" },
);
if (generated.status !== 0) {
  process.stderr.write(generated.stderr);
  process.exit(generated.status ?? 1);
}
const vector = JSON.parse(generated.stdout);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));

const importStarted = performance.now();
const { default: createModule } = await import(pathToFileURL(modulePath));
const { validatePresentedToken } = await import(
  pathToFileURL(resolve(dirname(modulePath), "sd_cwt_webcrypto.mjs"))
);
const imported = performance.now();
const module = await createModule();
const initialized = performance.now();

const protectedHeader = bytes(vector.protectedHeader);
const payload = bytes(vector.payload);
const empty = new Uint8Array();
const prepared = module.prepareSignature(protectedHeader, payload, empty);
assert.deepEqual(prepared, bytes(vector.toBeSigned));

const finalized = module.finalizeSignature(
  protectedHeader,
  payload,
  bytes(vector.signature),
);
assert.deepEqual(finalized, bytes(vector.token));

const presented = module.present(
  bytes(vector.token),
  vector.selected.map(bytes),
);
assert.deepEqual(presented, bytes(vector.presented));

const publicKey = await webcrypto.subtle.importKey(
  "jwk",
  vector.publicJwk,
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["verify"],
);
const validation = await validatePresentedToken(
  module,
  presented,
  publicKey,
  webcrypto,
);
assert.deepEqual(validation.claims, bytes(vector.claims));
assert.deepEqual(validation.clear, bytes(vector.clear));
assert.deepEqual(validation.disclosed, bytes(vector.disclosed));

const mutableToken = new Uint8Array(presented);
const pendingValidation = validatePresentedToken(
  module,
  mutableToken,
  publicKey,
  webcrypto,
);
mutableToken.fill(0);
const stableValidation = await pendingValidation;
assert.deepEqual(stableValidation.claims, bytes(vector.claims));

await assert.rejects(() =>
  validatePresentedToken(
    module,
    bytes(vector.foreignPresented),
    publicKey,
    webcrypto,
  ),
);
for (const testCase of vector.validationCases) {
  const result = await validatePresentedToken(
    module,
    bytes(testCase.token),
    publicKey,
    webcrypto,
  );
  assert.deepEqual(result.claims, bytes(testCase.claims));
  assert.deepEqual(result.clear, bytes(testCase.clear));
  assert.deepEqual(result.disclosed, bytes(testCase.disclosed));
}

const key = await webcrypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign", "verify"],
);
assert.equal(key.privateKey.extractable, false);
const browserSignature = new Uint8Array(
  await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key.privateKey,
    prepared,
  ),
);
module.finalizeSignature(protectedHeader, payload, browserSignature);
assert.equal(
  await webcrypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key.publicKey,
    browserSignature,
    prepared,
  ),
  true,
);

const iterations = 2_000;
const benchmark = (operation) => {
  const started = performance.now();
  for (let index = 0; index < iterations; ++index) operation();
  return ((performance.now() - started) * 1_000) / iterations;
};
const metrics = {
  importMs: imported - importStarted,
  initializeMs: initialized - imported,
  iterations,
  presentUs: benchmark(() =>
    module.present(bytes(vector.token), vector.selected.map(bytes)),
  ),
  prepareSignatureUs: benchmark(() =>
    module.prepareSignature(protectedHeader, payload, empty),
  ),
  finalizeSignatureUs: benchmark(() =>
    module.finalizeSignature(protectedHeader, payload, browserSignature),
  ),
};
const verificationIterations = 100;
const verificationStarted = performance.now();
for (let index = 0; index < verificationIterations; ++index) {
  await validatePresentedToken(module, presented, publicKey, webcrypto);
}
metrics.verificationIterations = verificationIterations;
metrics.verifyPresentedTokenMs =
  (performance.now() - verificationStarted) / verificationIterations;

console.log(
  "WASM/Python byte conformance, WebCrypto signing, and disclosure verification passed",
);
console.log(JSON.stringify(metrics, null, 2));
