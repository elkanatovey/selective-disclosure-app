"use strict";

const $ = (sel) => document.querySelector(sel);

const docEl = $("#doc");
const verifyDocEl = $("#verify-doc");

let chunks = [];
let revealed = new Set();

// --- rendering --------------------------------------------------------------
// Document text is untrusted input, so it only ever reaches the DOM through
// textContent. Redaction is a CSS class, not a substitution, so the holder can
// flip a chunk back without re-fetching anything.

function renderHolder() {
  const frag = document.createDocumentFragment();
  chunks.forEach((text, i) => {
    const span = document.createElement("span");
    span.className = revealed.has(i) ? "chunk" : "chunk redacted";
    span.dataset.i = String(i);
    span.textContent = text;
    frag.appendChild(span);
  });
  docEl.replaceChildren(frag);
  updateCounter();
}

function renderVerified(spans) {
  // A withheld chunk's length is unknown to the verifier; every full chunk is
  // the same width, so the widest revealed one gives the bar its size.
  const size = spans.reduce((m, s) => (s === null ? m : Math.max(m, s.length)), 0);
  const bar = "\u00a0".repeat(size || 30);
  const frag = document.createDocumentFragment();
  spans.forEach((text, i) => {
    const span = document.createElement("span");
    span.className = text === null ? "chunk redacted" : "chunk";
    span.dataset.i = String(i);
    span.textContent = text === null ? bar : text;
    frag.appendChild(span);
  });
  verifyDocEl.replaceChildren(frag);
}

function updateCounter() {
  $("#counter").textContent = `${revealed.size} / ${chunks.length} chunks revealed`;
}

function setOut(sel, html) {
  $(sel).innerHTML = html;
}

// --- selection --------------------------------------------------------------

function selectedIndices(container) {
  const sel = window.getSelection();
  if (!sel || sel.isCollapsed || !sel.rangeCount) return [];
  const range = sel.getRangeAt(0);
  const out = [];
  for (const span of container.children) {
    if (range.intersectsNode(span)) out.push(Number(span.dataset.i));
  }
  return out;
}

function applyToSelection(makeRevealed) {
  const picked = selectedIndices(docEl);
  if (!picked.length) return;
  for (const i of picked) {
    makeRevealed ? revealed.add(i) : revealed.delete(i);
    docEl.children[i].classList.toggle("redacted", !revealed.has(i));
  }
  updateCounter();
  window.getSelection().removeAllRanges();
}

function setAll(makeRevealed) {
  revealed = makeRevealed ? new Set(chunks.keys()) : new Set();
  renderHolder();
}

function invert() {
  revealed = new Set([...chunks.keys()].filter((i) => !revealed.has(i)));
  renderHolder();
}

// --- api --------------------------------------------------------------------

async function detail(res) {
  try {
    return (await res.json()).detail || res.statusText;
  } catch {
    return res.statusText;
  }
}

async function issue() {
  const text = $("#text").value;
  const size = Number($("#size").value) || 30;
  const res = await fetch("/api/issue", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text, size }),
  });
  if (!res.ok) return setOut("#issue-out", `<span class="bad">${await detail(res)}</span>`);

  const data = await res.json();
  chunks = data.chunks;
  revealed = new Set(chunks.keys());
  $("#panel-holder").classList.remove("is-hidden");
  renderHolder();
  setOut(
    "#issue-out",
    `<dl>
       <dt>chunks</dt><dd>${data.chunk_count}</dd>
       <dt>chunk size</dt><dd>${data.size} characters</dd>
       <dt>signed token</dt><dd>${data.token_bytes.toLocaleString()} bytes, fully redacted</dd>
     </dl>`
  );
}

async function presentBlob() {
  const res = await fetch("/api/present", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ reveal: [...revealed] }),
  });
  if (!res.ok) throw new Error(await detail(res));
  return res.blob();
}

async function exportPresentation() {
  try {
    const url = URL.createObjectURL(await presentBlob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "presentation.cose";
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    setOut("#issue-out", `<span class="bad">${err.message}</span>`);
  }
}

async function verifyBlob(blob) {
  const body = new FormData();
  body.append("token", blob, "presentation.cose");
  const res = await fetch("/api/verify", { method: "POST", body });
  if (!res.ok) return setOut("#verify-out", `<span class="bad">${await detail(res)}</span>`);

  const data = await res.json();
  const mark = (ok) => (ok ? '<span class="ok">pass</span>' : '<span class="bad">fail</span>');
  setOut(
    "#verify-out",
    `<dl>
       <dt>issuer signature</dt><dd>${mark(data.signature_ok)}</dd>
       <dt>disclosure hashes</dt><dd>${mark(data.disclosures_ok)}</dd>
       <dt>field</dt><dd>${data.field_revealed ? "revealed" : "withheld"}</dd>
       <dt>chunks committed</dt><dd>${data.chunk_count}</dd>
       <dt>revealed</dt><dd>${data.revealed_count}</dd>
       <dt>withheld</dt><dd>${data.withheld_count}</dd>
       ${data.error ? `<dt>error</dt><dd class="bad">${data.error}</dd>` : ""}
     </dl>`
  );
  renderVerified(data.spans || []);
}

// --- wiring -----------------------------------------------------------------

// Pressing a toolbar button would otherwise collapse the document selection
// before the click handler could read it.
for (const id of ["#btn-reveal-sel", "#btn-hide-sel"]) {
  $(id).addEventListener("mousedown", (ev) => ev.preventDefault());
}

$("#btn-issue").addEventListener("click", issue);
$("#btn-reveal-sel").addEventListener("click", () => applyToSelection(true));
$("#btn-hide-sel").addEventListener("click", () => applyToSelection(false));
$("#btn-all").addEventListener("click", () => setAll(true));
$("#btn-none").addEventListener("click", () => setAll(false));
$("#btn-invert").addEventListener("click", invert);
$("#btn-export").addEventListener("click", exportPresentation);

$("#file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (file) $("#text").value = await file.text();
});

$("#vfile").addEventListener("change", (ev) => {
  const file = ev.target.files[0];
  if (file) verifyBlob(file);
});

$("#btn-verify-current").addEventListener("click", async () => {
  try {
    await verifyBlob(await presentBlob());
  } catch (err) {
    setOut("#verify-out", `<span class="bad">${err.message}</span>`);
  }
});
