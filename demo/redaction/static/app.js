"use strict";

const $ = (sel) => document.querySelector(sel);

const docEl = $("#doc");
const verifyDocEl = $("#verify-doc");

// null text = withheld in the loaded statement: no opening exists, so it can
// never be revealed here, only rendered as locked.
let chunks = [];
let chunkChars = 6;
let kept = new Set();

// --- rendering --------------------------------------------------------------
// Statement text is untrusted input and only ever reaches the DOM through
// textContent. Redaction is a CSS class, so toggling never re-fetches.

function bar(n) {
  return "\u00a0".repeat(n);
}

function renderDoc() {
  const frag = document.createDocumentFragment();
  chunks.forEach((text, i) => {
    const span = document.createElement("span");
    const locked = text === null;
    span.className = locked
      ? "chunk redacted locked"
      : kept.has(i)
        ? "chunk"
        : "chunk redacted";
    span.dataset.i = String(i);
    span.textContent = locked ? bar(chunkChars) : text;
    frag.appendChild(span);
  });
  docEl.replaceChildren(frag);
  updateCounter();
}

function renderVerified(spans) {
  const frag = document.createDocumentFragment();
  spans.forEach((text) => {
    const span = document.createElement("span");
    span.className = text === null ? "chunk redacted" : "chunk";
    span.textContent = text === null ? bar(chunkChars) : text;
    frag.appendChild(span);
  });
  verifyDocEl.replaceChildren(frag);
}

function openable() {
  return chunks.reduce((n, t) => (t === null ? n : n + 1), 0);
}

function updateCounter() {
  const locked = chunks.length - openable();
  const note = locked ? ` (${locked} locked)` : "";
  $("#counter").textContent = `${kept.size} / ${openable()} chunks kept${note}`;
}

function setOut(sel, html) {
  $(sel).innerHTML = html;
}

// --- selection --------------------------------------------------------------

function applyToSelection(keep) {
  const sel = window.getSelection();
  if (!sel || sel.isCollapsed || !sel.rangeCount) return;
  const range = sel.getRangeAt(0);
  for (const span of docEl.children) {
    if (!range.intersectsNode(span)) continue;
    const i = Number(span.dataset.i);
    if (chunks[i] === null) continue; // locked: no opening to restore
    keep ? kept.add(i) : kept.delete(i);
    span.classList.toggle("redacted", !kept.has(i));
  }
  updateCounter();
  sel.removeAllRanges();
}

function setAll(keep) {
  kept = new Set();
  if (keep) chunks.forEach((t, i) => t !== null && kept.add(i));
  renderDoc();
}

function invert() {
  const next = new Set();
  chunks.forEach((t, i) => t !== null && !kept.has(i) && next.add(i));
  kept = next;
  renderDoc();
}

// --- api --------------------------------------------------------------------

async function detail(res) {
  try {
    return (await res.json()).detail || res.statusText;
  } catch {
    return res.statusText;
  }
}

function adopt(data) {
  chunks = data.chunks;
  chunkChars = data.chunk_chars;
  kept = new Set();
  chunks.forEach((t, i) => t !== null && kept.add(i));
  $("#panel-redact").classList.remove("is-hidden");
  renderDoc();

  const receipt = !data.has_receipt
    ? '<span class="warn">absent</span>'
    : data.receipt_ok
      ? '<span class="ok">verified</span>'
      : '<span class="bad">FAILED</span>';
  const fields = Object.entries(data.fields)
    .map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`)
    .join("");
  setOut(
    "#load-out",
    `<dl>
       <dt>chunks</dt><dd>${data.chunk_count} of ${data.chunk_chars} characters</dd>
       <dt>statement</dt><dd>${data.token_bytes.toLocaleString()} bytes</dd>
       <dt>receipt</dt><dd>${receipt}</dd>
       ${fields}
     </dl>`
  );
}

async function loadStatement() {
  const body = new FormData();
  const tok = $("#token").files[0];
  if (!tok) return setOut("#load-out", '<span class="bad">choose a .cose file</span>');
  body.append("token", tok);
  if ($("#cert").files[0]) body.append("service_cert", $("#cert").files[0]);

  const res = await fetch("/api/load", { method: "POST", body });
  if (!res.ok) return setOut("#load-out", `<span class="bad">${await detail(res)}</span>`);
  adopt(await res.json());
}

async function issueSample() {
  const res = await fetch("/api/sample", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: $("#sample-text").value }),
  });
  if (!res.ok) return setOut("#load-out", `<span class="bad">${await detail(res)}</span>`);
  adopt(await res.json());
}

async function restrictedBlob() {
  const res = await fetch("/api/restrict", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ keep: [...kept] }),
  });
  if (!res.ok) throw new Error(await detail(res));
  return res.blob();
}

async function exportStatement() {
  try {
    const url = URL.createObjectURL(await restrictedBlob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "redacted.cose";
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    setOut("#load-out", `<span class="bad">${err.message}</span>`);
  }
}

async function verifyBlob(blob, cert) {
  const body = new FormData();
  body.append("token", blob, "statement.cose");
  if (cert) body.append("service_cert", cert);

  const res = await fetch("/api/verify", { method: "POST", body });
  if (!res.ok) return setOut("#verify-out", `<span class="bad">${await detail(res)}</span>`);

  const d = await res.json();
  const mark = (ok) => (ok ? '<span class="ok">pass</span>' : '<span class="bad">fail</span>');
  const receipt = !d.has_receipt
    ? '<span class="warn">absent</span>'
    : mark(d.receipt_ok);
  setOut(
    "#verify-out",
    `<dl>
       <dt>receipt</dt><dd>${receipt}</dd>
       <dt>disclosure hashes</dt><dd>${mark(d.disclosures_ok)}</dd>
       <dt>chunks committed</dt><dd>${d.chunk_count}</dd>
       <dt>revealed</dt><dd>${d.revealed_count}</dd>
       <dt>withheld</dt><dd>${d.chunk_count - d.revealed_count}</dd>
       ${d.error ? `<dt>error</dt><dd class="bad">${d.error}</dd>` : ""}
     </dl>`
  );
  renderVerified(d.chunks || []);
}

// --- wiring -----------------------------------------------------------------

// Pressing a toolbar button would otherwise collapse the document selection
// before the click handler could read it.
for (const id of ["#btn-reveal-sel", "#btn-hide-sel"]) {
  $(id).addEventListener("mousedown", (ev) => ev.preventDefault());
}

$("#btn-load").addEventListener("click", loadStatement);
$("#btn-sample").addEventListener("click", issueSample);
$("#btn-reveal-sel").addEventListener("click", () => applyToSelection(true));
$("#btn-hide-sel").addEventListener("click", () => applyToSelection(false));
$("#btn-all").addEventListener("click", () => setAll(true));
$("#btn-none").addEventListener("click", () => setAll(false));
$("#btn-invert").addEventListener("click", invert);
$("#btn-export").addEventListener("click", exportStatement);

$("#vtoken").addEventListener("change", (ev) => {
  const file = ev.target.files[0];
  if (file) verifyBlob(file, $("#vcert").files[0]);
});

$("#btn-verify-current").addEventListener("click", async () => {
  try {
    await verifyBlob(await restrictedBlob(), $("#vcert").files[0]);
  } catch (err) {
    setOut("#verify-out", `<span class="bad">${err.message}</span>`);
  }
});
