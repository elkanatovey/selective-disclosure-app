import { compare, decode, encode, Tag, unb64 } from "./cbor.js";
import { RCK, redactReport, STATEMENT_HEADERS } from "./report-profile.js";
const coseKey = (jwk) =>
  new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, unb64(jwk.x)],
    [-3, unb64(jwk.y)],
  ]);
const publicJwk = (jwk) => ({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y });
export async function generateSigner() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
      "verify",
    ]),
    jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, publicJwk: publicJwk(jwk) };
}
export async function importSigner(source) {
  let jwk;
  if (source.trim().startsWith("{")) jwk = JSON.parse(source);
  else {
    const match = source.match(/-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/);
    if (!match) throw new TypeError("key must be a PKCS#8 PEM or private JWK");
    const der = Uint8Array.from(atob(match[1].replace(/\s/g, "")), (c) => c.charCodeAt(0)),
      temporary = await crypto.subtle.importKey(
        "pkcs8",
        der,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"],
      );
    jwk = await crypto.subtle.exportKey("jwk", temporary);
  }
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d || !jwk.x || !jwk.y)
    throw new TypeError("key must be a private P-256 key");
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  return { privateKey, publicJwk: publicJwk(jwk) };
}
export async function issueReport(subject, report, msrcJwk, endorse, signer) {
  if (!subject.trim()) throw new TypeError("subject is required");
  signer ??= await generateSigner();
  const endorsement = await endorse(signer.publicJwk),
    iat = Math.floor(Date.now() / 1000),
    redacted = await redactReport(report);
  const protectedBytes = encode(
    new Map([
      ...STATEMENT_HEADERS,
      [
        15,
        new Map([
          [1, endorsement.issuer],
          [2, subject.trim()],
          [6, iat],
        ]),
      ],
      [33, [unb64(endorsement.leaf), unb64(endorsement.root)]],
    ]),
  );
  const payloadBytes = encode(
    new Map([
      [1, endorsement.issuer],
      [6, iat],
      [8, new Map([[1, coseKey(msrcJwk)]])],
      [RCK, redacted.digests],
    ]),
  );
  const toSign = encode(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]),
    signature = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.privateKey, toSign),
    ),
    token = encode(new Tag(18, [protectedBytes, new Map(), payloadBytes, signature]));
  return { token, disclosures: redacted.disclosures, serial: endorsement.serial };
}
export function present(transparent, issued) {
  const tagged = decode(unb64(transparent));
  if (!(tagged instanceof Tag) || tagged.tag !== 18) throw new Error("SCITT returned invalid COSE");
  const parts = tagged.value,
    stripped = encode(new Tag(18, [parts[0], new Map(), parts[2], parts[3]]));
  if (compare(stripped, issued.token) !== 0)
    throw new Error("SCITT returned a different statement");
  if (!(parts[1] instanceof Map) || !parts[1].has(394)) throw new Error("SCITT receipt is missing");
  parts[1].set(17, issued.disclosures);
  return encode(tagged);
}
