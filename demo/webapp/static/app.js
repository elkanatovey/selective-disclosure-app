"use strict";

// --- tiny helpers -----------------------------------------------------------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  kids.forEach((k) => n.append(k));
  return n;
};

async function api(method, path, body, isJson = true) {
  const opts = { method, headers: {} };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body !== undefined) {
    opts.headers["content-type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  const data = isJson ? await r.json().catch(() => ({})) : await r.text();
  if (!r.ok) throw new Error(data.detail || r.statusText);
  return data;
}
const getJSON = (p) => api("GET", p);
const postJSON = (p, b) => api("POST", p, b);

function renderFields(container, fields) {
  container.replaceChildren();
  if (!fields || fields.length === 0) {
    container.append(el("p", { className: "muted", textContent: "(nothing revealed)" }));
    return;
  }
  for (const f of fields) {
    let val = f.value;
    if (f.kind === "list") val = "[" + f.value.join(", ") + "]";
    if (f.kind === "hex") val = "0x" + f.value;
    container.append(
      el("div", { className: "kv" },
        el("span", { className: "k", textContent: f.name }),
        el("span", { className: "v", textContent: String(val) })
      )
    );
  }
}

// --- health + live event feed (all pages) -----------------------------------
async function pollHealth() {
  const pill = $("#health");
  try {
    const h = await getJSON("/api/health");
    if (!h.node_up) throw new Error("node down");
    pill.className = h.signing_key_ready ? "pill pill-ok" : "pill pill-wait";
    pill.textContent = h.signing_key_ready
      ? `node up · key ready`
      : `node up · key NOT initialised`;
    pill.title = `app ${h.version.app_version} · ${h.version.ccf_version}`;
  } catch (e) {
    pill.className = "pill pill-err";
    pill.textContent = "node unreachable";
  }
}

function tickerAdd(text) {
  const list = $("#ticker-list");
  if (!list) return;
  const item = el("li", {}, el("time", { textContent: new Date().toLocaleTimeString() }), " " + text);
  list.prepend(item);
  while (list.children.length > 40) list.lastChild.remove();
}

function describe(ev) {
  switch (ev.kind) {
    case "report":
      return ev.parent ? `follow-up committed ${ev.txid} → ${ev.parent}` : `report committed ${ev.txid}`;
    case "disclosure":
      return `disclosure ${ev.artifact_id} for ${ev.txid}: [${ev.revealed.join(", ")}]`;
    case "signing_key":
      return ev.created ? `signing key ${ev.rotate ? "rotated" : "initialised"} (${ev.txid})` : "signing key already present";
    default:
      return ev.kind;
  }
}

const wsHandlers = [];
function onEvent(fn) { wsHandlers.push(fn); }

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const sock = new WebSocket(`${proto}://${location.host}/ws`);
  sock.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    tickerAdd(describe(ev));
    if (ev.kind === "signing_key") pollHealth();
    wsHandlers.forEach((fn) => fn(ev));
  };
  sock.onclose = () => setTimeout(connectWS, 1500);
}

// --- Member -----------------------------------------------------------------
function initMember() {
  const out = $("#member-out");
  const call = async (rotate) => {
    out.textContent = "…";
    try {
      const r = await postJSON(`/api/member/signing-key?rotate=${rotate}`, {});
      out.textContent = JSON.stringify(r, null, 2);
    } catch (e) { out.textContent = "error: " + e.message; }
  };
  $("#init-key").onclick = () => call(false);
  $("#rotate-key").onclick = () => call(true);
}

// --- Client -----------------------------------------------------------------
function initClient() {
  const form = $("#report-form");
  form.onsubmit = async (e) => {
    e.preventDefault();
    const result = $("#client-result");
    try {
      const r = await api("POST", "/api/client/reports", new FormData(form));
      $("#r-txid").textContent = r.txid;
      $("#r-bytes").textContent = r.token_bytes;
      $("#r-leak").innerHTML = r.leaked_fields.length
        ? `⚠ plaintext leaked on the wire: ${r.leaked_fields.join(", ")}`
        : `✓ no submitted plaintext appears in the token bytes`;
      renderFields($("#r-public"), r.public_view);
      result.classList.remove("hidden");
    } catch (err) { alert("submit failed: " + err.message); }
  };
}

// --- Operator ---------------------------------------------------------------
function initOperator() {
  let selected = null;

  async function loadLedger() {
    const { statements } = await getJSON("/api/ledger");
    const list = $("#ledger-list");
    list.replaceChildren();
    statements.forEach((txid) => {
      const li = el("li", { textContent: txid });
      li.onclick = () => select(txid, li);
      if (txid === selected) li.classList.add("active");
      list.append(li);
    });
  }

  function select(txid, li) {
    selected = txid;
    $$("#ledger-list li").forEach((n) => n.classList.toggle("active", n === li));
    $("#sel-txid").textContent = txid;
    $("#read-full").disabled = false;
    $("#disclose").disabled = false;
    $("#followup-btn").disabled = false;
    $("#full-fields").replaceChildren();
    $("#disclose-result").replaceChildren();
    $("#anon-note").textContent = "";
  }

  $("#refresh-ledger").onclick = loadLedger;

  $("#read-full").onclick = async () => {
    try {
      const r = await getJSON(`/api/operator/full/${selected}`);
      renderFields($("#full-fields"), r.fields);
      $("#anon-note").textContent =
        `an anonymous caller to the same endpoint → ${r.anon_status} (refused)`;
    } catch (e) { alert(e.message); }
  };

  $("#disclose").onclick = async () => {
    const fields = $$("#disclosure-choices input:checked").map((c) => c.value);
    if (!fields.length) return alert("pick at least one field");
    try {
      const r = await postJSON(`/api/operator/disclose/${selected}`, { fields });
      renderFields($("#disclose-result"), r.revealed);
    } catch (e) { alert(e.message); }
  };

  onEvent((ev) => { if (ev.kind === "report") loadLedger(); });
  loadLedger();

  $("#followup-form").onsubmit = async (e) => {
    e.preventDefault();
    if (!selected) return;
    try {
      const r = await api("POST", `/api/operator/followup/${selected}`, new FormData(e.target));
      $("#followup-out").textContent = `follow-up committed ${r.txid}, bound to ${r.parent}`;
      e.target.reset();
    } catch (err) { alert("follow-up failed: " + err.message); }
  };
}

// --- Researcher -------------------------------------------------------------
function initResearcher() {
  const pick = $("#artifact-pick");
  const verifyBtn = $("#verify");

  async function loadArtifacts() {
    const { artifacts } = await getJSON("/api/artifacts");
    const cur = pick.value;
    pick.replaceChildren(el("option", { value: "", textContent: "— released disclosures —" }));
    artifacts.forEach((a) =>
      pick.append(el("option", { value: a.id, textContent: `${a.id} · ${a.txid} · [${a.revealed.join(", ")}]` }))
    );
    pick.value = cur;
    verifyBtn.disabled = !pick.value;
  }

  pick.onchange = () => { verifyBtn.disabled = !pick.value; };

  verifyBtn.onclick = async () => {
    try {
      const r = await postJSON("/api/researcher/verify", { artifact_id: pick.value });
      $("#verify-result").classList.remove("hidden");
      $("#v-status").innerHTML = r.verified
        ? `✓ signature valid · statement ${r.txid}`
        : `⚠ verification failed: ${r.error}`;
      renderFields($("#v-revealed"), r.revealed || []);
      $("#v-hidden").textContent = r.hidden ? `still hidden: ${r.hidden.join(", ")}` : "";
    } catch (e) { alert(e.message); }
  };

  onEvent((ev) => { if (ev.kind === "disclosure") loadArtifacts(); });
  loadArtifacts();
}

// --- Wall -------------------------------------------------------------------
function initWall() {
  const list = $("#wall-list");
  onEvent((ev) => {
    list.prepend(el("li", { className: `wall-${ev.kind}` },
      el("time", { textContent: new Date().toLocaleTimeString() }),
      " " + describe(ev)));
  });
}

// --- boot -------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  pollHealth();
  setInterval(pollHealth, 5000);
  connectWS();
  if ($("#member-out")) initMember();
  if ($("#report-form")) initClient();
  if ($("#ledger-list")) initOperator();
  if ($("#artifact-pick")) initResearcher();
  if ($("#wall-list")) initWall();
});
