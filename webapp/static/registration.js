import { b64 } from "./sdcwt.js";

async function responseError(response) {
  const fallback = response.statusText || `HTTP ${response.status}`;
  try {
    const data = await response.json();
    return new Error(data.detail || fallback);
  } catch {
    return new Error(fallback);
  }
}

async function verifiedBytes(response, description) {
  if (
    response.headers.get("content-type")?.split(";", 1)[0] !== "application/cose" ||
    response.headers.get("x-receipt-verified") !== "true"
  ) {
    throw new Error(`${description} receipt was not verified`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!bytes.length) throw new Error(`${description} response is incomplete`);
  return bytes;
}

export async function register(path, token) {
  const response = await fetch(`${path}?waitForCommit=true`, {
    method: "POST",
    headers: { "content-type": "application/cose" },
    body: token,
  });
  if (response.status !== 201) throw await responseError(response);
  await verifiedBytes(response, "SCITT registration");
  const txid = response.headers.get("x-ms-ccf-transaction-id");
  if (!txid) throw new Error("SCITT registration response is incomplete");

  for (let attempt = 0; attempt < 100; attempt++) {
    const fetched = await fetch(`${path}/${encodeURIComponent(txid)}/statement`);
    if ([202, 503].includes(fetched.status)) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      continue;
    }
    if (fetched.status !== 200) throw await responseError(fetched);
    const statement = await verifiedBytes(fetched, "SCITT statement");
    return { txid, transparent: b64(statement) };
  }
  throw new Error(`SCITT statement ${txid} remained unavailable`);
}
