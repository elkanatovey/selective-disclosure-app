import assert from "node:assert/strict";
import test from "node:test";
import { ReviewModel } from "../../webapp/static/review-model.js";

function loadedReport(txid = "1.1") {
  const fields = new Map();
  for (let key = 1000; key <= 1008; key++) {
    fields.set(key, { key, opening: key, value: "value", children: [] });
  }
  fields.get(1007).value = new Uint8Array(16);
  fields.get(1002).children = [0, 1].map((index) => ({
    index,
    value: "chunk",
    opening: `body-${index}`,
  }));
  fields.get(1006).children = [{ index: 0, value: "reference", opening: "reference-0" }];
  return { report: { fields, statement: new Uint8Array([1]) }, verified: { txid } };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function readyModel() {
  const model = new ReviewModel("https://verifier.example");
  await model.load(async () => loadedReport());
  return model;
}

test("selection is plain data and includes each required ancestor once", async () => {
  const model = await readyModel();
  model.selectAll(false);
  for (const id of ["field:1001", "body:0", "body:1", "reference:0", "field:1007"]) {
    model.setSelected(id, true);
  }
  assert.deepEqual(model.selectedOpenings(), [1001, 1002, "body-0", "body-1", 1006, "reference-0"]);
  assert.equal(model.selected.has("field:1007"), false);
  assert.equal(model.allSelected("body"), true);
  assert.equal("input" in model.report.fields.get(1002).children[0], false);
  model.selectAll(false, "body");
  assert.deepEqual(model.selectedOpenings(), [1001, 1006, "reference-0"]);
});

test("export is enabled only for the current signed selection", async () => {
  const model = await readyModel();
  const token = new Uint8Array([2]);
  assert.equal(await model.sign(async () => token), true);
  assert.equal(model.canExport, true);
  model.setSelected("body:0", false);
  assert.equal(model.canExport, false);
  assert.equal(model.token, undefined);
});

for (const change of ["selection", "audience", "report"]) {
  test(`late signing response cannot overwrite changed ${change}`, async () => {
    const model = await readyModel(),
      pending = deferred();
    const signing = model.sign(() => pending.promise);
    assert.equal(model.phase, "signing");
    if (change === "selection") model.setSelected("body:0", false);
    if (change === "audience") model.setAudience("https://other.example");
    if (change === "report") await model.load(async () => loadedReport("1.2"));
    pending.resolve(new Uint8Array([3]));
    assert.equal(await signing, false);
    assert.equal(model.canExport, false);
    assert.equal(model.token, undefined);
  });
}

test("newer imports win over earlier responses", async () => {
  const model = new ReviewModel(),
    pending = deferred();
  const first = model.load(() => pending.promise);
  await model.load(async () => loadedReport("1.2"));
  pending.resolve(loadedReport("1.1"));
  assert.equal(await first, false);
  assert.equal(model.verified.txid, "1.2");
});

test("audience changes during import do not discard the report", async () => {
  const model = new ReviewModel(),
    pending = deferred();
  const loading = model.load(() => pending.promise);
  model.setAudience("https://verifier.example");
  model.selectAll(false);
  pending.resolve(loadedReport());
  assert.equal(await loading, true);
  assert.equal(model.canSign, true);
});

test("a stale signing error cannot invalidate a newer token", async () => {
  const model = await readyModel(),
    pending = deferred();
  const first = model.sign(() => pending.promise);
  model.setAudience("https://other.example");
  await model.sign(async () => new Uint8Array([4]));
  pending.reject(new Error("old failure"));
  await first;
  assert.equal(model.canExport, true);
  assert.deepEqual(model.token, new Uint8Array([4]));
  assert.equal(model.error, "");
});

test("failed signing and empty selection cannot be exported", async () => {
  const model = await readyModel();
  assert.equal(
    await model.sign(async () => {
      throw new Error("unavailable");
    }),
    false,
  );
  assert.equal(model.phase, "error");
  assert.equal(model.error, "unavailable");
  assert.equal(model.canExport, false);
  model.selectAll(false);
  assert.equal(model.canSign, false);
});
