import assert from "node:assert/strict";
import test from "node:test";
import {b64, decode, encode, generateSigner, inspectStatement, issueReport, present, Simple} from "../assets/sdcwt.js";

for (const [name, encoded] of [
  ["identical", "a201616101616a"],
  ["short integer", "a20161611801616a"],
  ["long integer", "a2182a0119002a02"],
  ["negative integer", "a22061613800616a"],
  ["text", "a261610178016102"],
  ["nested map", "a1182aa20100180101"],
  ["redaction marker", "a2f83b80f83b80"],
]) {
  test(`rejects duplicate CBOR keys: ${name}`, () => {
    assert.throws(() => decode(new Uint8Array(Buffer.from(encoded, "hex"))), /duplicate CBOR map key/);
  });
}

test("distinct key types and non-preferred encodings remain readable", () => {
  const map = new Map([[1, "integer"], ["1", "text"], [new Simple(59), []]]);
  const decoded = decode(encode(map));
  assert.equal(decoded.size, 3);
  assert.equal(decoded.get(1), "integer");
  assert.equal(decoded.get("1"), "text");
  assert.deepEqual(decode(new Uint8Array(Buffer.from("a2180101180202", "hex"))), new Map([[1, 1], [2, 2]]));
});

async function fullReport(report = {title: "Report", body: "abcdefghijklmnopqr", references: ["first", "second"]}) {
  const signer = await generateSigner();
  const issued = await issueReport("test", report, signer.publicJwk,
    async () => ({issuer: "test", signature: "AQ", authorityPublicJwk: signer.publicJwk}), signer);
  const tagged = decode(issued.token);
  tagged.value[1].set(394, []);
  return present(b64(encode(tagged)), issued);
}

for (const missing of ["last body chunk", "all body chunks", "reference", "all nested openings", "top-level field"]) {
  test(`full report rejects missing ${missing} while partial inspection allows it`, async () => {
    const tagged = decode(await fullReport());
    tagged.value[1].set(17, tagged.value[1].get(17).filter(encoded => {
      const claim = decode(encoded);
      if (missing === "last body chunk") return !(claim.length === 3 && claim[2] === 2);
      if (missing === "all body chunks") return !(claim.length === 3 && claim[2] < 1000);
      if (missing === "reference") return !(claim.length === 2 && claim[1] === "second");
      if (missing === "all nested openings") return claim.length === 3 && claim[2] >= 1000;
      return claim[2] !== 1001;
    }));
    const statement = encode(tagged);
    await assert.rejects(inspectStatement(statement), /disclosure is missing/);
    await assert.doesNotReject(inspectStatement(statement, false));
  });
}

test("complete reports and empty containers are still accepted", async () => {
  const full = await inspectStatement(await fullReport());
  assert.equal(full.fields.get(1002).children.map(child => child.value).join(""), "abcdefghijklmnopqr");
  assert.deepEqual(full.fields.get(1006).children.map(child => child.value), ["first", "second"]);
  const empty = await inspectStatement(await fullReport({body: "", references: []}));
  assert.deepEqual(empty.fields.get(1002).children, []);
  assert.deepEqual(empty.fields.get(1006).children, []);
});