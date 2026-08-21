# SD-CWT browser WebAssembly feasibility slice

This target compiles the existing EverCBOR-backed C++ token code to browser
WebAssembly without compiling CCF or `ccfcrypto`. It demonstrates three useful
protocol operations:

- attach selected disclosures to an issued SD-CWT with `present`;
- prepare the COSE `Sig_structure` and finalize a COSE_Sign1 around an
  asynchronous WebCrypto ECDSA signature;
- verify an issuer signature, hash-match nested/map/array/decoy disclosures,
  reject unmatched disclosures, and reconstruct clear/disclosed claims.

The native CCF application and the WASM module use the same CBOR,
presentation, and COSE framing sources. QCBOR is not used.

## Reproducible build

The SDK version matches `.github/workflows/wasm.yml`:

```sh
git submodule update --init third_party/CCF
git clone --depth 1 --branch 4.0.12 \
  https://github.com/emscripten-core/emsdk.git /tmp/emsdk
/tmp/emsdk/emsdk install 4.0.12
/tmp/emsdk/emsdk activate 4.0.12
source /tmp/emsdk/emsdk_env.sh

emcmake cmake -GNinja -S app/wasm -B /tmp/sd-cwt-wasm-build \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/sd-cwt-wasm-build
```

Install the existing Python conformance package and run the Node/browser API
test. Python is an independent test oracle only; it is not loaded or shipped by
the browser module:

```sh
python3 -m venv /tmp/sd-cwt-wasm-venv
/tmp/sd-cwt-wasm-venv/bin/pip install -e "./tools/sd_cwt[test]"
PYTHON=/tmp/sd-cwt-wasm-venv/bin/python \
  node app/wasm/tests/conformance.mjs \
  /tmp/sd-cwt-wasm-build/sd_cwt.mjs
```

Build products stay under `/tmp` and are not committed.

## Browser API

The generated ES module exposes `Uint8Array` operations for presentation,
COSE signing, and staged verification. Signing and verification are split
because WebCrypto is asynchronous; no private key enters WASM. The 764-byte
coordinator contains only WebCrypto calls, not protocol logic.

```js
import createSdCwt from "./sd_cwt.mjs";
import { validatePresentedToken } from "./sd_cwt_webcrypto.mjs";

const sdCwt = await createSdCwt();
const externalAad = new Uint8Array();
const toBeSigned = sdCwt.prepareSignature(
  protectedHeader,
  payload,
  externalAad,
);
const signature = new Uint8Array(
  await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    toBeSigned,
  ),
);
const token = sdCwt.finalizeSignature(
  protectedHeader,
  payload,
  signature,
);
const disclosed = sdCwt.present(token, selectedDisclosures);
const validated = await validatePresentedToken(
  sdCwt,
  disclosed,
  issuerPublicKey,
);
// validated.clear and validated.disclosed are CDE-encoded CBOR maps.
```

`privateKey` can be a non-exportable `CryptoKey`. The conformance test generates
one and verifies the resulting signature with WebCrypto.

## Observed overhead

Measured on 2026-08-21 in the Azure Linux 3 dev container with Emscripten
4.0.12, its Node 22.16.0, and a Release build:

| Item | Raw | gzip -9 |
| --- | ---: | ---: |
| `sd_cwt.wasm` | 131,354 B | 44,581 B |
| `sd_cwt.mjs` | 36,160 B | 10,064 B |
| `sd_cwt_webcrypto.mjs` | 764 B | 414 B |
| Total | 168,278 B | 55,059 B |

- Clean configure and build: 7 seconds, excluding SDK download/install.
- ES module import: 2.48-4.19 ms.
- WASM module initialization: 8.52-13.76 ms.
- Presentation: 98.42-108.11 microseconds per call over 2,000 iterations.
- Signature preparation: 41.59-50.25 microseconds per call over 2,000
  iterations.
- Signature finalization: 66.26-93.80 microseconds per call over 2,000
  iterations.
- End-to-end presented-token verification: 0.49-0.77 ms per call over 100
  iterations,
  including WebCrypto ECDSA verification, one disclosure digest, WASM matching,
  and claim reconstruction.

These are single-process feasibility measurements, not browser benchmarks. The
repository has no current JavaScript SD-CWT/COSE implementation, so there is no
meaningful existing-JavaScript runtime baseline. WebCrypto signing time is
intentionally excluded from the WASM framing timings. Python runs only to
generate fresh expected vectors for the test and is not part of these timings.

The implementation adds one portable EverCBOR adapter, one extracted
presentation translation unit, a staged disclosure verifier, two small COSE
phase functions, an Embind file, a standalone CMake target, one cross-language
test pair, a 764-byte WebCrypto coordinator, and one CI workflow.
The complete patch is 2,225 insertions and 237 deletions across 32 files;
1,394 physical lines are the new portable adapter, presentation/verifier,
bindings, standalone build, and WebCrypto coordinator. The balance is tests,
CI, documentation, and native call-site migration.

## Coupling and remaining work

The WASM target depends on EverCBOR headers and `CBORNondet.c` from the pinned
CCF submodule. It has no CCF headers, CCF symbols, OpenSSL, private-key code, or
ECDSA implementation. Native issuance still uses CCF for entropy, SHA-2, EC
key metadata, and ECDSA. The app's request and persistence serializers also
still use `ccf::cbor`, but are outside the token/WASM target.

Complete browser issuance needs a staged API around the existing redaction
logic: WebCrypto `getRandomValues` supplies salts and padding, the C++ core
encodes disclosures, `subtle.digest` computes their hashes, and a second C++
phase inserts those hashes and prepares the issuer signature. Holder `cnf`
coordinates should be passed as public data. This avoids Asyncify and a second
SHA implementation.

Presentation attachment and SD-CWT disclosure validation are complete for the
project's existing C++ token value types. The verifier enforces the issuer
signature result, definite CBOR parsing, depth/key/date limits, non-empty
`sd_claims`, recursive hash reachability, decoys, and duplicate disclosed keys.
The caller still chooses the trusted issuer public key and applies clock,
audience, and application policy. The portable EverCBOR adapter does not decode
floating-point claim values; this project currently issues integer dates only.

KBT support should follow the same pattern: move existing KBT protected-header
and payload construction into a prepare phase, sign with the holder's
non-exportable WebCrypto key, then finalize with the shared COSE function.

## Security assessment

Benefits:

- private keys remain non-exportable WebCrypto objects and are never copied to
  linear WASM memory;
- native and browser framing use the same EverCBOR and C++ protocol code,
  reducing cross-language drift;
- browser verification uses WebCrypto plus the shared C++ matcher, with Python
  retained only as an independent conformance oracle;
- the WASM build excludes CCF, OpenSSL, and an embedded signing stack.

Limitations:

- non-exportable keys can still be used by compromised page JavaScript, so CSP,
  dependency integrity, and XSS prevention remain essential;
- WASM memory is not an enclave and the module has not received a side-channel
  or independent security audit;
- the caller must select a trusted issuer key and use the high-level WebCrypto
  coordinator; the low-level staged API accepts WebCrypto results and is not a
  separate security boundary;
- temporal validity, audience, and application policy remain caller concerns;
- the measured size includes Embind and exception support and may change with
  toolchain versions.
