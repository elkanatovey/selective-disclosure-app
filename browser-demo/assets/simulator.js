import {
  Simple,
  Tag,
  b64,
  coseKey,
  decode,
  encode,
  inspectStatement,
  jwkFromCose,
  signKbt,
} from "./sdcwt.js";

const DATABASE_VERSION = 1;
const DATABASE_PREFIX = "evld-browser-demo-v1";
const CHANNEL_PREFIX = "evld-browser-demo";
const ISSUER = "did:web:local-disclosure-authority.invalid";
const REDACTED_CLAIMS = 17;
const RECEIPTS = 394;
const RESEARCHER_KEY = 1000;
const ENDORSEMENT_SIGNATURE = 1001;
const AUTHORITY_KEY = 1002;
const redactedClaimsKey = map => [...map.keys()].find(key => key instanceof Simple && key.value === 59);

const toHex = bytes => [...bytes].map(value => value.toString(16).padStart(2, "0")).join("");
const equalBytes = (left, right) => left.length === right.length && left.every((value, index) => value === right[index]);
const hash = async bytes => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const importVerifier = jwk => crypto.subtle.importKey("jwk", jwk, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
const sign = (key, bytes) => crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, key, bytes).then(value => new Uint8Array(value));
const verify = (key, signature, bytes) => crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, signature, bytes);

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}

function databaseName(session) {
  return `${DATABASE_PREFIX}:${session}`;
}

function openDatabase(session) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName(session), DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      database.createObjectStore("meta", {keyPath: "key"});
      database.createObjectStore("reports", {keyPath: "txid"});
      database.createObjectStore("deliveries", {keyPath: "txid"});
      database.createObjectStore("disclosures", {keyPath: "id"});
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function readRecord(session, storeName, key) {
  const database = await openDatabase(session);
  const transaction = database.transaction(storeName, "readonly");
  const done = transactionDone(transaction);
  const result = await requestResult(transaction.objectStore(storeName).get(key));
  await done;
  database.close();
  return result;
}

async function readAll(session, storeName) {
  const database = await openDatabase(session);
  const transaction = database.transaction(storeName, "readonly");
  const done = transactionDone(transaction);
  const result = await requestResult(transaction.objectStore(storeName).getAll());
  await done;
  database.close();
  return result;
}

async function writeRecord(session, storeName, value) {
  const database = await openDatabase(session);
  const transaction = database.transaction(storeName, "readwrite");
  const done = transactionDone(transaction);
  transaction.objectStore(storeName).put(value);
  await done;
  database.close();
}

async function withLock(session, name, operation) {
  if (!navigator.locks) {
    throw new Error("This demo requires the Web Locks API. Use a current version of Chrome, Edge, Firefox, or Safari.");
  }
  return navigator.locks.request(`${DATABASE_PREFIX}:${session}:${name}`, operation);
}

async function generateSigner() {
  const keys = await crypto.subtle.generateKey(
    {name: "ECDSA", namedCurve: "P-256"},
    false,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  return {privateKey: keys.privateKey, publicJwk};
}

async function ensureConfiguration(session) {
  return withLock(session, "configuration", async () => {
    const existing = await readRecord(session, "meta", "configuration");
    if (existing) return existing;
    const authority = await generateSigner();
    const transparency = await generateSigner();
    const configuration = {
      key: "configuration",
      authorityPrivateKey: authority.privateKey,
      authorityPublicJwk: authority.publicJwk,
      transparencyPrivateKey: transparency.privateKey,
      transparencyPublicJwk: transparency.publicJwk,
      issuer: ISSUER,
      createdAt: Date.now(),
    };
    await writeRecord(session, "meta", configuration);
    return configuration;
  });
}

function announce(session, type, detail = {}) {
  const channel = new BroadcastChannel(`${CHANNEL_PREFIX}:${session}`);
  channel.postMessage({type, detail, at: Date.now()});
  channel.close();
}

export function subscribe(session, callback) {
  const channel = new BroadcastChannel(`${CHANNEL_PREFIX}:${session}`);
  channel.onmessage = event => callback(event.data);
  return () => channel.close();
}

export function getSession() {
  const parameters = new URLSearchParams(location.search);
  let session = parameters.get("session") || localStorage.getItem(`${DATABASE_PREFIX}:active`);
  if (!session) {
    session = crypto.randomUUID();
    localStorage.setItem(`${DATABASE_PREFIX}:active`, session);
  }
  session = session.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 64) || crypto.randomUUID();
  localStorage.setItem(`${DATABASE_PREFIX}:active`, session);
  return session;
}

export function setSession(session) {
  localStorage.setItem(`${DATABASE_PREFIX}:active`, session);
}

export async function resetSession(session, nextSession) {
  await new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(databaseName(session));
    request.onsuccess = resolve;
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("Close other demo tabs before resetting this session"));
  });
  announce(session, "reset", {nextSession});
}

export async function publicConfiguration(session) {
  const configuration = await ensureConfiguration(session);
  return {
    issuer: configuration.issuer,
    authorityPublicJwk: configuration.authorityPublicJwk,
    transparencyPublicJwk: configuration.transparencyPublicJwk,
    serviceName: "Local Transparency Service simulation",
  };
}

export async function endorseIssuer(session, publicJwk) {
  const configuration = await ensureConfiguration(session);
  const encodedKey = encode(coseKey(publicJwk));
  const signature = await sign(configuration.authorityPrivateKey, encodedKey);
  return {
    issuer: configuration.issuer,
    signature: b64(signature),
    authorityPublicJwk: configuration.authorityPublicJwk,
    serial: toHex(crypto.getRandomValues(new Uint8Array(8))),
  };
}

function coseParts(value) {
  const tagged = value instanceof Uint8Array ? decode(value) : value;
  if (!(tagged instanceof Tag) || tagged.tag !== 18 || !Array.isArray(tagged.value) || tagged.value.length !== 4) {
    throw new Error("expected a COSE Sign1 message");
  }
  return tagged.value;
}

function bareStatement(statement) {
  const [protectedBytes, , payloadBytes, signature] = coseParts(statement);
  return encode(new Tag(18, [protectedBytes, new Map(), payloadBytes, signature]));
}

async function verifyStatement(statement, configuration) {
  const [protectedBytes, , payloadBytes, signature] = coseParts(statement);
  const protectedHeader = decode(protectedBytes);
  if (protectedHeader.get(1) !== -7 || protectedHeader.get(16) !== 293 || protectedHeader.get(170) !== -16) {
    throw new Error("unsupported SD-CWT profile");
  }
  const researcherCoseKey = protectedHeader.get(RESEARCHER_KEY);
  if (!(researcherCoseKey instanceof Map)) throw new Error("researcher key is missing");
  const endorsementSignature = protectedHeader.get(ENDORSEMENT_SIGNATURE);
  const authorityCoseKey = protectedHeader.get(AUTHORITY_KEY);
  if (!(endorsementSignature instanceof Uint8Array) || !(authorityCoseKey instanceof Map)) {
    throw new Error("authority endorsement is missing");
  }
  if (!equalBytes(encode(authorityCoseKey), encode(coseKey(configuration.authorityPublicJwk)))) {
    throw new Error("statement is not endorsed by this Disclosure Authority");
  }
  const authorityVerifier = await importVerifier(configuration.authorityPublicJwk);
  if (!await verify(authorityVerifier, endorsementSignature, encode(researcherCoseKey))) {
    throw new Error("researcher endorsement signature is invalid");
  }
  const researcherVerifier = await importVerifier(jwkFromCose(researcherCoseKey));
  const toBeSigned = encode(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
  if (!await verify(researcherVerifier, signature, toBeSigned)) {
    throw new Error("researcher statement signature is invalid");
  }
  const payload = decode(payloadBytes);
  const issuer = protectedHeader.get(15)?.get(1);
  if (issuer !== configuration.issuer || payload.get(1) !== configuration.issuer) {
    throw new Error("statement issuer does not match the Disclosure Authority");
  }
  return {
    payload,
    protectedHeader,
    subject: protectedHeader.get(15)?.get(2) || "",
    researcherPublicJwk: jwkFromCose(researcherCoseKey),
  };
}

async function merkleProof(leaves, targetIndex) {
  let level = leaves.map(value => new Uint8Array(value));
  let index = targetIndex;
  const proof = [];
  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? Math.min(index + 1, level.length - 1) : index - 1;
    proof.push([siblingIndex < index ? 0 : 1, level[siblingIndex]]);
    const next = [];
    for (let position = 0; position < level.length; position += 2) {
      const right = level[Math.min(position + 1, level.length - 1)];
      next.push(await hash(new Uint8Array([...level[position], ...right])));
    }
    level = next;
    index = Math.floor(index / 2);
  }
  return {root: level[0], proof};
}

function receiptPayload(receipt) {
  return encode(new Map([
    [1, receipt.txid],
    [2, receipt.statementHash],
    [3, receipt.root],
    [4, receipt.proof],
    [5, receipt.index],
    [6, receipt.size],
    [7, receipt.issuedAt],
  ]));
}

function encodeReceipt(receipt) {
  return encode(new Map([
    [1, receipt.txid],
    [2, receipt.statementHash],
    [3, receipt.root],
    [4, receipt.proof],
    [5, receipt.index],
    [6, receipt.size],
    [7, receipt.issuedAt],
    [8, receipt.signature],
  ]));
}

function decodeReceipt(bytes) {
  const value = decode(bytes);
  if (!(value instanceof Map)) throw new Error("receipt is not a CBOR map");
  return {
    txid: value.get(1),
    statementHash: value.get(2),
    root: value.get(3),
    proof: value.get(4),
    index: value.get(5),
    size: value.get(6),
    issuedAt: value.get(7),
    signature: value.get(8),
  };
}

function attachReceipt(statement, receipt) {
  const [protectedBytes, headers, payloadBytes, signature] = coseParts(statement);
  const transparentHeaders = new Map(headers);
  transparentHeaders.set(RECEIPTS, [encodeReceipt(receipt)]);
  return encode(new Tag(18, [protectedBytes, transparentHeaders, payloadBytes, signature]));
}

export async function registerStatement(session, statement) {
  return withLock(session, "log", async () => {
    const configuration = await ensureConfiguration(session);
    const verified = await verifyStatement(statement, configuration);
    const existing = (await readAll(session, "reports")).sort((left, right) => left.sequence - right.sequence);
    const statementHash = await hash(statement);
    const leaves = [...existing.map(report => report.statementHash), statementHash];
    const sequence = existing.length + 1;
    const txid = `1.${sequence}`;
    const inclusion = await merkleProof(leaves, sequence - 1);
    const receipt = {
      txid,
      statementHash,
      root: inclusion.root,
      proof: inclusion.proof,
      index: sequence - 1,
      size: sequence,
      issuedAt: Math.floor(Date.now() / 1000),
    };
    receipt.signature = await sign(configuration.transparencyPrivateKey, receiptPayload(receipt));
    const transparent = attachReceipt(statement, receipt);
    await writeRecord(session, "reports", {
      txid,
      sequence,
      subject: verified.subject,
      statement,
      statementHash,
      transparent,
      createdAt: Date.now(),
    });
    announce(session, "report-registered", {txid});
    return {txid, receipt: encodeReceipt(receipt), transparent};
  });
}

async function verifyReceipt(statement, configuration) {
  const [, headers] = coseParts(statement);
  const receipts = headers.get(RECEIPTS);
  if (!Array.isArray(receipts) || receipts.length !== 1) throw new Error("transparency receipt is missing");
  const receipt = decodeReceipt(receipts[0]);
  const statementHash = await hash(bareStatement(statement));
  if (!equalBytes(statementHash, receipt.statementHash)) throw new Error("receipt does not bind this statement");
  let root = statementHash;
  for (const [side, sibling] of receipt.proof) {
    root = side === 0
      ? await hash(new Uint8Array([...sibling, ...root]))
      : await hash(new Uint8Array([...root, ...sibling]));
  }
  if (!equalBytes(root, receipt.root)) throw new Error("Merkle inclusion proof is invalid");
  const transparencyVerifier = await importVerifier(configuration.transparencyPublicJwk);
  if (!await verify(transparencyVerifier, receipt.signature, receiptPayload(receipt))) {
    throw new Error("transparency receipt signature is invalid");
  }
  return receipt;
}

export async function deliverToAuthority(session, statement) {
  const configuration = await ensureConfiguration(session);
  const verified = await verifyStatement(statement, configuration);
  const receipt = await verifyReceipt(statement, configuration);
  await inspectStatement(statement);
  await writeRecord(session, "deliveries", {
    txid: receipt.txid,
    subject: verified.subject,
    statement,
    deliveredAt: Date.now(),
  });
  announce(session, "report-delivered", {txid: receipt.txid});
  return {txid: receipt.txid};
}

export async function listDeliveries(session) {
  return (await readAll(session, "deliveries")).sort((left, right) => right.deliveredAt - left.deliveredAt);
}

export async function inspectDelivery(session, txid) {
  const delivery = await readRecord(session, "deliveries", txid);
  if (!delivery) throw new Error("submitted report was not found");
  const configuration = await ensureConfiguration(session);
  const verified = await verifyStatement(delivery.statement, configuration);
  const receipt = await verifyReceipt(delivery.statement, configuration);
  const model = await inspectStatement(delivery.statement);
  return {delivery, verified, receipt, model};
}

export async function createDisclosure(session, txid, selected, audience) {
  return withLock(session, `disclosure:${txid}`, async () => {
    const inspected = await inspectDelivery(session, txid);
    const configuration = await ensureConfiguration(session);
    const signer = {
      privateKey: configuration.authorityPrivateKey,
      publicJwk: configuration.authorityPublicJwk,
    };
    const token = await signKbt(inspected.model, selected, signer, audience);
    const id = `${txid}:${crypto.randomUUID()}`;
    await writeRecord(session, "disclosures", {
      id,
      txid,
      subject: inspected.verified.subject,
      audience: audience.trim(),
      token,
      createdAt: Date.now(),
    });
    announce(session, "disclosure-created", {id, txid});
    return {id, token};
  });
}

export async function listDisclosures(session) {
  return (await readAll(session, "disclosures")).sort((left, right) => right.createdAt - left.createdAt);
}

async function disclosureConsistency(statement) {
  const [, headers, payloadBytes] = coseParts(statement);
  const openings = headers.get(REDACTED_CLAIMS);
  if (!Array.isArray(openings) || openings.length === 0) throw new Error("no disclosures were presented");
  const payload = decode(payloadBytes);
  const rootKey = redactedClaimsKey(payload);
  const roots = payload.get(rootKey);
  if (!Array.isArray(roots) || roots.length !== 9) throw new Error("report schema is invalid");
  const indexed = new Map();
  for (const encoded of openings) {
    const key = b64(await hash(encode(encoded)));
    if (indexed.has(key)) throw new Error("duplicate disclosure opening was presented");
    indexed.set(key, decode(encoded));
  }
  const reachable = new Set();
  for (const rootHash of roots) {
    const rootId = b64(rootHash);
    const opening = indexed.get(rootId);
    if (!opening) continue;
    reachable.add(rootId);
    const value = opening[1];
    if (value instanceof Map) {
      const nestedKey = redactedClaimsKey(value);
      for (const nestedHash of value.get(nestedKey) || []) {
        const nestedId = b64(nestedHash);
        if (indexed.has(nestedId)) reachable.add(nestedId);
      }
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (!(item instanceof Tag) || item.tag !== 60) continue;
        const nestedId = b64(item.value);
        if (indexed.has(nestedId)) reachable.add(nestedId);
      }
    }
  }
  if (reachable.size !== indexed.size) throw new Error("a presented disclosure is not reachable from the signed report");
}

function reportFromModel(model, subject, txid) {
  const value = key => model.fields.get(key)?.value;
  const body = model.fields.get(1002);
  let bodyResult = {known: false, chunks: []};
  if (body) {
    const nestedKey = body.value instanceof Map ? redactedClaimsKey(body.value) : undefined;
    const count = nestedKey ? body.value.get(nestedKey).length : 0;
    const chunks = Array(count).fill(null);
    for (const child of body.children) chunks[child.index] = child.value;
    bodyResult = {known: true, chunks};
  }
  const references = model.fields.get(1006)?.children.map(child => child.value) || [];
  const fingerprint = value(1005);
  const patchDate = value(1008);
  return {
    subject,
    txid,
    fields: {
      title: value(1001),
      component: value(1003),
      severity: value(1004),
      fingerprint: fingerprint instanceof Uint8Array ? toHex(fingerprint) : undefined,
      patch: typeof value(1007) === "string" ? value(1007) : undefined,
      patch_date: Number.isInteger(patchDate) ? new Date(patchDate * 1000).toISOString().slice(0, 10) : undefined,
    },
    body: bodyResult,
    references,
  };
}

export async function verifyDisclosure(session, token, expectedAudience) {
  const checks = [];
  const passed = (name, detail) => checks.push({name, detail, status: "pass"});
  const failed = (name, detail) => checks.push({name, detail, status: "fail"});
  try {
    const configuration = await ensureConfiguration(session);
    const [protectedBytes, , payloadBytes, signature] = coseParts(token);
    const protectedHeader = decode(protectedBytes);
    if (protectedHeader.get(1) !== -7 || protectedHeader.get(16) !== 294 || !(protectedHeader.get(13) instanceof Tag)) {
      throw new Error("unsupported KBT profile");
    }
    passed("COSE envelopes and algorithms", "Expected KBT and SD-CWT profiles");

    const statement = encode(protectedHeader.get(13));
    const statementVerification = await verifyStatement(statement, configuration);
    passed("Issuer trust and signature", "Authority endorsement and researcher signature");

    const receipt = await verifyReceipt(statement, configuration);
    passed("Transparency receipt", "Signed receipt matches the registered statement");

    const authorityKey = statementVerification.payload.get(8)?.get(1);
    if (!(authorityKey instanceof Map) || !equalBytes(encode(authorityKey), encode(coseKey(configuration.authorityPublicJwk)))) {
      throw new Error("KBT key is not bound to the Disclosure Authority");
    }
    const authorityVerifier = await importVerifier(jwkFromCose(authorityKey));
    const toBeSigned = encode(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
    const kbtPayload = decode(payloadBytes);
    if (!await verify(authorityVerifier, signature, toBeSigned)) throw new Error("KBT signature is invalid");
    if (kbtPayload.get(3) !== expectedAudience.trim()) throw new Error("KBT audience does not match");
    if (!Number.isSafeInteger(kbtPayload.get(6))) throw new Error("KBT issued-at claim is invalid");
    passed("KBT proof and audience", "Authority signature, audience, and issued-at");

    await disclosureConsistency(statement);
    const model = await inspectStatement(statement, false);
    passed("Disclosure consistency", "Disclosures match the signed report");
    passed("Merkle inclusion", "Receipt proves inclusion in the local log");

    return {
      valid: true,
      checks,
      report: reportFromModel(model, statementVerification.subject, receipt.txid),
    };
  } catch (error) {
    failed("Verification stopped", error.message);
    return {valid: false, checks, report: undefined};
  }
}
