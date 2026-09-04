import {
  getSession,
  listDisclosures,
  subscribe,
  verifyDisclosure,
} from "./simulator.js";

const byId = id => document.getElementById(id);
const labels = {title: "Title", component: "Component", severity: "Severity", fingerprint: "Fingerprint", patch: "Patch", patch_date: "Patch date"};
const session = getSession();
let token;

const sessionUrl = path => `${path}?session=${encodeURIComponent(session)}`;

function field(label, value) {
  const row = document.createElement("div");
  row.className = "field-row";
  const name = document.createElement("label");
  name.textContent = label;
  const content = value == null ? document.createElement("span") : document.createElement("code");
  if (value == null) content.className = "redacted-value";
  else content.textContent = value;
  row.append(name, content);
  return row;
}

function renderReport(report) {
  byId("report-subject").textContent = report?.subject || "Untrusted disclosure";
  byId("report-txid").textContent = report?.txid || "Not verified";
  byId("field-list").replaceChildren();
  for (const [name, label] of Object.entries(labels)) byId("field-list").append(field(label, report?.fields?.[name]));
  byId("body-preview").replaceChildren();
  if (report?.body?.known) {
    for (const chunk of report.body.chunks) {
      const span = document.createElement("span");
      if (chunk == null) {
        span.className = "redacted";
        span.textContent = "██████";
      } else {
        span.textContent = chunk;
      }
      byId("body-preview").append(span);
    }
  } else {
    const span = document.createElement("span");
    span.className = "redacted";
    span.textContent = "████████████";
    byId("body-preview").append(span);
  }
  byId("references").replaceChildren();
  if (Array.isArray(report?.references) && report.references.length) {
    for (const value of report.references) {
      const row = document.createElement("div");
      row.className = "reference";
      row.textContent = value;
      byId("references").append(row);
    }
  } else {
    byId("references").append(field("", null).lastChild);
  }
}

function renderChecks(result) {
  byId("checks").replaceChildren();
  for (const check of result.checks) {
    const row = document.createElement("div");
    row.className = `check ${check.status}`;
    const icon = document.createElement("i");
    icon.dataset.lucide = check.status === "pass" ? "circle-check" : "circle-alert";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("small");
    title.textContent = check.name;
    detail.textContent = check.detail;
    copy.append(title, detail);
    row.append(icon, copy);
    byId("checks").append(row);
  }
  byId("overall").className = `overall ${result.valid ? "pass" : "fail"}`;
  byId("overall-title").textContent = result.valid ? "Disclosure verified" : "Verification failed";
  byId("overall-detail").textContent = result.valid ? "All checks passed" : "Do not rely on disclosed contents";
  lucide.createIcons();
}

function load(value, title, detail) {
  token = new Uint8Array(value);
  byId("file-title").textContent = title;
  byId("file-detail").textContent = detail;
  byId("verify").disabled = false;
  byId("results").hidden = true;
  byId("verify-error").textContent = "";
}

async function refreshDisclosures(autoLoad = false) {
  const disclosures = await listDisclosures(session);
  byId("disclosure-list").replaceChildren();
  if (!disclosures.length) {
    const empty = document.createElement("div");
    empty.className = "available-empty";
    empty.textContent = "No disclosures yet. Sign one in the Authority tab.";
    byId("disclosure-list").append(empty);
    return;
  }
  for (const disclosure of disclosures) {
    const item = document.createElement("div");
    item.className = "available-item";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = disclosure.subject;
    const detail = document.createElement("small");
    detail.textContent = `${disclosure.txid} · ${new Date(disclosure.createdAt).toLocaleTimeString()}`;
    copy.append(title, detail);
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Load";
    button.onclick = () => load(disclosure.token, `Disclosure for ${disclosure.subject}`, `${disclosure.token.length.toLocaleString()} B · ${disclosure.txid}`);
    item.append(copy, button);
    byId("disclosure-list").append(item);
  }
  if (autoLoad) {
    const latest = disclosures[0];
    load(latest.token, `Disclosure for ${latest.subject}`, `${latest.token.length.toLocaleString()} B · ${latest.txid}`);
  }
}

byId("token-file").onchange = async event => {
  const file = event.target.files[0];
  if (file) load(new Uint8Array(await file.arrayBuffer()), file.name, `${file.size.toLocaleString()} B`);
};
for (const event of ["dragenter", "dragover"]) byId("drop-zone").addEventListener(event, () => byId("drop-zone").classList.add("dragging"));
for (const event of ["dragleave", "drop"]) byId("drop-zone").addEventListener(event, () => byId("drop-zone").classList.remove("dragging"));
byId("drop-zone").ondrop = async event => {
  event.preventDefault();
  const file = event.dataTransfer.files[0];
  if (file) load(new Uint8Array(await file.arrayBuffer()), file.name, `${file.size.toLocaleString()} B`);
};
byId("drop-zone").ondragover = event => event.preventDefault();
byId("verify-form").onsubmit = async event => {
  event.preventDefault();
  try {
    byId("verify").disabled = true;
    byId("verify-error").textContent = "";
    const result = await verifyDisclosure(session, token, byId("audience").value);
    renderReport(result.report);
    renderChecks(result);
    byId("verify-form").hidden = true;
    byId("results").hidden = false;
  } catch (error) {
    byId("verify-error").textContent = error.message;
  } finally {
    byId("verify").disabled = false;
  }
};
byId("audience").oninput = () => byId("results").hidden = true;
byId("verify-another").onclick = () => {
  byId("results").hidden = true;
  byId("verify-form").hidden = false;
  byId("token-file").value = "";
  token = undefined;
  byId("verify").disabled = true;
  byId("file-title").textContent = "Or choose a disclosure file";
  byId("file-detail").textContent = "Select a `.kbt.cose` file";
  refreshDisclosures().catch(error => byId("verify-error").textContent = error.message);
};
byId("session-id").textContent = `Session ${session.slice(0, 8)}`;
byId("launcher-link").href = sessionUrl("index.html");
byId("previous-link").href = sessionUrl("authority.html");
subscribe(session, event => {
  if (event.type === "disclosure-created") refreshDisclosures(true).catch(error => byId("verify-error").textContent = error.message);
  if (event.type === "reset" && event.detail.nextSession) location.search = `?session=${encodeURIComponent(event.detail.nextSession)}`;
});
refreshDisclosures().catch(error => byId("verify-error").textContent = error.message);
lucide.createIcons();
