import * as simulator from "../assets/simulator.js";
import * as sdCwt from "../assets/sdcwt.js";

const session = `test-${crypto.randomUUID()}`;
const audience = "https://browser-test.example/verifier";
const report = {
  title: "Parser crash",
  body: "A crafted header causes an out-of-bounds read.",
  component: "archive-parser",
  severity: "high",
  fingerprint: "deadbeef",
  references: ["CVE-2026-1042"],
};

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function rejects(operation, pattern) {
  try {
    await operation();
  } catch (error) {
    assert(pattern.test(error.message), `unexpected rejection: ${error.message}`);
    return;
  }
  throw new Error(`expected rejection matching ${pattern}`);
}

async function issue(subject, configuration) {
  return sdCwt.issueReport(
    subject,
    report,
    configuration.authorityPublicJwk,
    publicJwk => simulator.endorseIssuer(session, publicJwk),
  );
}

async function submit(subject, configuration) {
  const issued = await issue(subject, configuration);
  const registered = await simulator.registerStatement(session, issued.token);
  const transparent = sdCwt.present(sdCwt.b64(registered.transparent), issued);
  await simulator.deliverToAuthority(session, transparent);
  return registered;
}

async function verifyPopupFallback() {
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.src = `../?session=${encodeURIComponent(session)}`;
  document.body.append(frame);
  await new Promise((resolve, reject) => {
    frame.onload = resolve;
    frame.onerror = () => reject(new Error("launcher test frame did not load"));
  });

  const launcher = frame.contentDocument;
  const results = [{}, null, null, {}, {}];
  frame.contentWindow.open = () => results.shift();
  launcher.getElementById("open-all").click();
  assert(launcher.getElementById("open-next").textContent === "Open Authority", "popup fallback did not select Authority");
  launcher.getElementById("open-next").click();
  assert(launcher.getElementById("open-next").textContent === "Open Verifier", "popup fallback did not select Verifier");
  launcher.getElementById("open-next").click();
  assert(launcher.getElementById("open-next").hidden, "popup fallback did not finish");
  frame.remove();
}

async function waitFor(predicate) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("browser test did not reach the expected state");
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

async function verifySigningInvalidation() {
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.src = `../authority.html?session=${encodeURIComponent(session)}`;
  const loaded = new Promise((resolve, reject) => {
    frame.onload = resolve;
    frame.onerror = () => reject(new Error("authority test frame did not load"));
  });
  document.body.append(frame);
  try {
    await loaded;
    const authority = frame.contentDocument;
    const byId = id => authority.getElementById(id);
    await waitFor(() => byId("delivery-list").querySelector("button"));
    const reviewButtons = [...byId("delivery-list").querySelectorAll("button")];
    const initialCount = (await simulator.listDisclosures(session)).length;
    for (const change of ["selection", "audience", "report", "back"]) {
      await reviewButtons[0].onclick();
      byId("clear-all").click();
      byId("field-1001").click();
      const body = byId("body-chunks").querySelector("input");
      body.checked = true;
      body.onchange();
      byId("audience").value = audience;
      byId("audience").oninput();

      let releaseLock, ready;
      const acquired = new Promise(resolve => ready = resolve);
      const lock = navigator.locks.request(`evld-browser-demo-v1:${session}:disclosure:${byId("report-txid").textContent}`,
        () => new Promise(resolve => { releaseLock = resolve; ready(); }));
      await acquired;
      const signing = byId("sign").onclick();
      try {
        if (change === "selection") { body.checked = false; body.onchange(); }
        if (change === "audience") { byId("audience").value = "https://changed.example"; byId("audience").oninput(); }
        if (change === "report") await reviewButtons[1].onclick();
        if (change === "back") byId("back").click();
      } finally {
        releaseLock();
        await lock;
        await signing;
      }
      assert(byId("export").disabled, `changed ${change} allowed a stale download`);
      assert((await simulator.listDisclosures(session)).length === initialCount, `changed ${change} persisted a stale disclosure`);
    }

    await reviewButtons[0].onclick();
    byId("clear-all").click();
    byId("field-1001").click();
    const body = byId("body-chunks").querySelector("input");
    body.checked = true;
    body.onchange();
    byId("audience").value = audience;
    byId("audience").oninput();

    const subtle = frame.contentWindow.crypto.subtle;
    const originalSign = subtle.sign;
    let releaseSign, ready;
    const started = new Promise(resolve => ready = resolve);
    let held = false;
    subtle.sign = async function(...args) {
      const signature = await originalSign.apply(this, args);
      if (!held) {
        held = true;
        await new Promise(resolve => { releaseSign = resolve; ready(); });
      }
      return signature;
    };
    try {
      const obsolete = byId("sign").onclick();
      await started;
      body.checked = false;
      body.onchange();
      const current = byId("sign").onclick();
      releaseSign();
      await Promise.all([obsolete, current]);
    } finally {
      releaseSign?.();
      subtle.sign = originalSign;
    }
    assert(!byId("export").disabled, "current selection could not be signed after cancellation");
    const disclosures = await simulator.listDisclosures(session);
    assert(disclosures.length === initialCount + 1, "in-flight cancellation persisted an obsolete token");
    const [disclosure] = disclosures;
    const checked = await simulator.verifyDisclosure(session, disclosure.token, audience);
    assert(checked.valid && !checked.report.body.known, "current signature disclosed an unchecked body");
  } finally {
    frame.remove();
  }
}

async function verifyFullDelivery(inspected) {
  const statement = inspected.delivery.statement;
  const lastIndex = inspected.model.fields.get(1002).children.at(-1).index;
  for (const missing of ["last body chunk", "all body chunks", "references", "all nested openings"]) {
    const tagged = sdCwt.decode(statement);
    tagged.value[1].set(17, tagged.value[1].get(17).filter(encoded => {
      const claim = sdCwt.decode(encoded);
      if (missing === "last body chunk") return !(claim.length === 3 && claim[2] === lastIndex);
      if (missing === "all body chunks") return !(claim.length === 3 && claim[2] < 1000);
      if (missing === "references") return claim.length === 3;
      return claim.length === 3 && claim[2] >= 1000;
    }));
    await rejects(() => simulator.deliverToAuthority(session, sdCwt.encode(tagged)), /disclosure is missing/);
  }
  const unchanged = await simulator.inspectDelivery(session, inspected.receipt.txid);
  assert(sdCwt.b64(unchanged.delivery.statement) === sdCwt.b64(statement), "invalid delivery replaced the stored report");
}

async function verifyDuplicateKeys(configuration, token) {
  const signer = await sdCwt.generateSigner();
  const issued = await sdCwt.issueReport("duplicate-issuer", report, configuration.authorityPublicJwk,
    publicJwk => simulator.endorseIssuer(session, publicJwk), signer);
  const tagged = sdCwt.decode(issued.token);
  const claims = sdCwt.decode(tagged.value[2]);
  claims.set(1, "discarded-issuer");
  const original = sdCwt.encode(claims), issuer = sdCwt.encode(configuration.issuer);
  const payload = new Uint8Array(original.length + 2 + issuer.length);
  payload.set(original);
  payload[0] = 0xa5;
  payload.set([0x18, 0x01], original.length);
  payload.set(issuer, original.length + 2);
  tagged.value[2] = payload;
  tagged.value[3] = new Uint8Array(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, signer.privateKey,
    sdCwt.encode(["Signature1", tagged.value[0], new Uint8Array(), payload])));
  await rejects(() => simulator.registerStatement(session, sdCwt.encode(tagged)), /duplicate CBOR map key/);

  const envelope = sdCwt.decode(token).value;
  const pieces = [new Uint8Array([0xd2, 0x84]), sdCwt.encode(envelope[0]),
    new Uint8Array([0xa2, 0x18, 0x2a, 1, 0x19, 0, 0x2a, 2]), sdCwt.encode(envelope[2]), sdCwt.encode(envelope[3])];
  const malformed = new Uint8Array(pieces.reduce((size, piece) => size + piece.length, 0));
  let offset = 0;
  for (const piece of pieces) { malformed.set(piece, offset); offset += piece.length; }
  const rejected = await simulator.verifyDisclosure(session, malformed, audience);
  assert(!rejected.valid && rejected.checks.some(check => /duplicate CBOR map key/.test(check.detail)),
    "verifier accepted duplicate unprotected keys");
}

async function run() {
  const configuration = await simulator.publicConfiguration(session);
  const first = await submit("case-one", configuration);
  const second = await submit("case-two", configuration);
  assert(first.txid === "1.1" && second.txid === "1.2", "log sequence is incorrect");

  const inspected = await simulator.inspectDelivery(session, second.txid);
  const title = inspected.model.fields.get(1001);
  const body = inspected.model.fields.get(1002);
  const references = inspected.model.fields.get(1006);
  const disclosure = await simulator.createDisclosure(
    session,
    second.txid,
    [title.opening, body.opening, body.children[0].opening, references.opening, references.children[0].opening],
    audience,
  );

  const valid = await simulator.verifyDisclosure(session, disclosure.token, audience);
  assert(valid.valid, "valid disclosure was rejected");
  assert(valid.checks.length === 6 && valid.checks.every(check => check.status === "pass"), "verification checks did not pass");
  assert(valid.report.body.chunks.filter(chunk => chunk !== null).length === 1, "body was not selectively disclosed");

  const wrongAudience = await simulator.verifyDisclosure(session, disclosure.token, "https://wrong.example");
  assert(!wrongAudience.valid, "wrong audience was accepted");

  const tampered = new Uint8Array(disclosure.token);
  tampered[tampered.length - 1] ^= 1;
  const tamperedResult = await simulator.verifyDisclosure(session, tampered, audience);
  assert(!tamperedResult.valid, "tampered disclosure was accepted");

  assert((await simulator.listDeliveries(session)).length === 2, "deliveries were not persisted");
  assert((await simulator.listDisclosures(session)).length === 1, "disclosure was not persisted");
  await verifyFullDelivery(inspected);
  await verifyDuplicateKeys(configuration, disclosure.token);
  await verifyPopupFallback();
  await verifySigningInvalidation();

  return {
    txids: [first.txid, second.txid],
    checks: valid.checks.map(check => check.name),
    wrongAudienceRejected: true,
    tamperingRejected: true,
    popupFallback: true,
    staleSigningRejected: true,
    incompleteDeliveriesRejected: true,
    duplicateKeysRejected: true,
  };
}

try {
  const result = await run();
  document.body.dataset.state = "passed";
  document.getElementById("result").textContent = JSON.stringify(result, null, 2);
} catch (error) {
  document.body.dataset.state = "failed";
  document.getElementById("result").textContent = error.stack || error.message;
}
