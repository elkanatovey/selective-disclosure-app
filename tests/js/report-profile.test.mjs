import assert from "node:assert/strict";
import test from "node:test";
import contracts from "../fixtures/report-profile.json" with { type: "json" };
import { b64, decode, encode, Simple } from "../../webapp/static/cbor.js";
import { generateSigner, issueReport } from "../../webapp/static/sdcwt.js";
import { inspectStatement, redactReport } from "../../webapp/static/report-profile.js";

for (const contract of contracts) {
  test(`browser report contract: ${contract.name}`, async (context) => {
    const signer = await generateSigner();
    let salt = 0;
    context.mock.method(crypto, "getRandomValues", (bytes) => bytes.fill(++salt));
    const issued = await issueReport(
      "contract",
      contract.report,
      signer.publicJwk,
      async () => ({ issuer: "contract-issuer", leaf: "AQ", root: "Ag" }),
      signer,
    );
    assert.deepEqual(issued.disclosures.map(b64), contract.disclosures);
    const token = decode(issued.token),
      payload = decode(token.value[2]);
    const marker = [...payload.keys()].find((key) => key instanceof Simple && key.value === 59);
    assert.deepEqual(payload.get(marker).map(b64), contract.digests);
    token.value[1].set(394, []);
    token.value[1].set(17, issued.disclosures);
    const inspected = await inspectStatement(encode(token));
    assert.deepEqual(
      inspected.fields.get(1002).children.map((child) => child.value),
      contract.bodyChunks,
    );
    assert.deepEqual(
      inspected.fields.get(1006).children.map((child) => child.value),
      contract.report.references,
    );
  });
}

for (const report of [
  { body: 3 },
  { severity: 5 },
  { references: [1] },
  { fingerprint: "xy" },
  { patch_date: 1.5 },
  { parent: "parent" },
  { unknown: true },
]) {
  test(`profile rejects invalid input ${JSON.stringify(report)}`, async () => {
    await assert.rejects(redactReport(report), TypeError);
  });
}

test("minimal and full reports have the same public shape and a padded parent", async () => {
  const signer = await generateSigner();
  const reports = [
    {},
    {
      title: "Full report",
      body: "Confidential report body",
      component: "parser",
      severity: "high",
      fingerprint: "deadbeef",
      references: ["CVE-2026-1042"],
      patch: "fixed in 1.2.3",
      patch_date: 1_788_739_200,
    },
  ];
  for (const report of reports) {
    const issued = await issueReport(
      "contract",
      report,
      signer.publicJwk,
      async () => ({ issuer: "contract-issuer", leaf: "AQ", root: "Ag" }),
      signer,
    );
    const payload = decode(decode(issued.token).value[2]);
    const marker = [...payload.keys()].find((key) => key instanceof Simple && key.value === 59);
    assert.deepEqual(
      [...payload.keys()].filter((key) => key !== marker),
      [1, 6, 8],
    );
    assert.equal(payload.get(marker).length, 9);
    const parent = issued.disclosures.map(decode).find((claim) => claim[2] === 1000)[1];
    assert.ok(parent instanceof Uint8Array);
    assert.equal(parent.length, 16);
  }
});

test("different reports encode the same fingerprint with independent openings", async () => {
  const openings = [];
  for (const body of ["First report body", "Different report body"]) {
    const report = await redactReport({ fingerprint: "deadbeef", body });
    const opening = report.disclosures.find((encoded) => decode(encoded)[2] === 1005);
    assert.deepEqual(decode(opening)[1], new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    openings.push(opening);
  }
  assert.notDeepEqual(openings[0], openings[1]);
});
