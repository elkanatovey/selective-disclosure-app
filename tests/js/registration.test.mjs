import assert from "node:assert/strict";
import test from "node:test";
import { register } from "../../webapp/static/registration.js";

const token = new Uint8Array([1]);
const verifiedHeaders = {
  "content-type": "application/cose",
  "x-receipt-verified": "true",
  "x-ms-ccf-transaction-id": "1.1",
};

function verifiedResponse(status, body = token) {
  return new Response(body, { status, headers: verifiedHeaders });
}

function mockFetch(context, responses) {
  context.mock.method(globalThis, "setTimeout", (callback) => callback());
  return context.mock.method(globalThis, "fetch", async () => {
    assert.ok(responses.length, "unexpected extra request");
    return responses.shift();
  });
}

for (const pending of [202, 503]) {
  test(`registration retries pending ${pending}`, async (context) => {
    const fetch = mockFetch(context, [
      verifiedResponse(201),
      new Response(null, { status: pending }),
      verifiedResponse(200, new Uint8Array([2])),
    ]);

    assert.deepEqual(await register("/entries", token), { txid: "1.1", transparent: "Ag" });
    assert.equal(fetch.mock.calls.length, 3);
    assert.equal(fetch.mock.calls[0].arguments[0], "/entries?waitForCommit=true");
    assert.equal(fetch.mock.calls[0].arguments[1].body, token);
    assert.equal(fetch.mock.calls[2].arguments[0], "/entries/1.1/statement");
  });
}

for (const stage of ["registration", "statement"]) {
  test(`rejects unverified ${stage}`, async (context) => {
    const unverified = new Response(token, {
      status: stage === "registration" ? 201 : 200,
      headers: { "content-type": "application/cose" },
    });
    mockFetch(
      context,
      stage === "registration" ? [unverified] : [verifiedResponse(201), unverified],
    );
    await assert.rejects(register("/entries", token), /receipt was not verified/);
  });

  test(`rejects empty ${stage}`, async (context) => {
    const empty = verifiedResponse(stage === "registration" ? 201 : 200, null);
    mockFetch(context, stage === "registration" ? [empty] : [verifiedResponse(201), empty]);
    await assert.rejects(register("/entries", token), /response is incomplete/);
  });
}

test("rejects a missing transaction ID", async (context) => {
  const response = verifiedResponse(201);
  response.headers.delete("x-ms-ccf-transaction-id");
  mockFetch(context, [response]);
  await assert.rejects(register("/entries", token), /response is incomplete/);
});

test("rejects an unexpected successful retrieval status", async (context) => {
  mockFetch(context, [verifiedResponse(201), new Response(null, { status: 204 })]);
  await assert.rejects(register("/entries", token), /HTTP 204/);
});

test("surfaces upstream errors without retrying", async (context) => {
  const response = Response.json({ detail: "unknown transaction" }, { status: 404 });
  mockFetch(context, [verifiedResponse(201), response]);
  await assert.rejects(register("/entries", token), /unknown transaction/);
});

test("stops retrying an unavailable statement", async (context) => {
  const pending = Array.from({ length: 100 }, () => new Response(null, { status: 202 }));
  const fetch = mockFetch(context, [verifiedResponse(201), ...pending]);
  await assert.rejects(register("/entries", token), /SCITT statement 1\.1 remained unavailable/);
  assert.equal(fetch.mock.calls.length, 101);
});
