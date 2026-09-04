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
  await verifyPopupFallback();

  return {
    txids: [first.txid, second.txid],
    checks: valid.checks.map(check => check.name),
    wrongAudienceRejected: true,
    tamperingRejected: true,
    popupFallback: true,
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
