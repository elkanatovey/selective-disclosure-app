import {b64, importSigner, issueReport, present} from "./sdcwt.js";
import {
  deliverToAuthority,
  endorseIssuer,
  getSession,
  publicConfiguration,
  registerStatement,
  subscribe,
} from "./simulator.js";

const byId = id => document.getElementById(id);
const defaults = {
  subject: "case-1042",
  title: "Parser crash in malformed archive",
  body: "A crafted header causes an out-of-bounds read.",
  component: "archive-parser",
  severity: "high",
  fingerprint: "f59f8e5c2488d8908652e86f3db35c35",
  references: "CVE-2026-1042",
  patch: "",
  patchDate: "",
};
const session = getSession();
let configuration;
let artifacts = {};

const optional = id => byId(id).value.trim() || undefined;
const sessionUrl = path => `${path}?session=${encodeURIComponent(session)}`;

function report() {
  const date = byId("patch-date").value;
  const references = byId("references").value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  return {
    title: optional("title"),
    body: optional("body"),
    component: optional("component"),
    severity: optional("severity"),
    fingerprint: optional("fingerprint"),
    references: references.length ? references : undefined,
    patch: optional("patch"),
    patch_date: date ? Math.floor(new Date(`${date}T00:00:00Z`).getTime() / 1000) : undefined,
  };
}

async function signer() {
  if (document.querySelector('[name="key-mode"]:checked').value === "generate") return undefined;
  const file = byId("issuer-key").files[0];
  if (!file) throw new Error("Select a PEM or JSON private key file");
  return importSigner(await file.text());
}

function status(state, title, detail) {
  byId("submission-status").dataset.state = state;
  byId("status-title").textContent = title;
  byId("status-detail").textContent = detail;
}

function download(value, name) {
  const link = document.createElement("a");
  link.href = `data:application/cose;base64,${value.replaceAll("-", "+").replaceAll("_", "/")}`;
  link.download = name;
  link.click();
}

byId("composer").addEventListener("submit", async event => {
  event.preventDefault();
  byId("error").textContent = "";
  byId("send").disabled = true;
  byId("confirmation").hidden = true;
  artifacts = {};
  try {
    status("working", "Preparing submission", "Signing report");
    const issued = await issueReport(
      byId("subject").value,
      report(),
      configuration.authorityPublicJwk,
      publicJwk => endorseIssuer(session, publicJwk),
      await signer(),
    );
    status("working", "Submitting report", "Recording commitment");
    const registered = await registerStatement(session, issued.token);
    const transparent = present(b64(registered.transparent), issued);
    status("working", "Completing submission", "Sending verified statement to Authority");
    const delivered = await deliverToAuthority(session, transparent);
    status("success", "Submission complete", "Registered and sent to the Disclosure Authority");
    artifacts = {redacted: b64(issued.token), full: b64(transparent)};
    byId("txid").textContent = delivered.txid;
    byId("redacted-size").textContent = `${issued.token.length.toLocaleString()} B`;
    byId("full-size").textContent = `${transparent.length.toLocaleString()} B`;
    byId("confirmation").hidden = false;
  } catch (error) {
    byId("error").textContent = error.message;
    status("error", "Submission failed", "Report was not submitted");
  } finally {
    byId("send").disabled = false;
  }
});

document.querySelectorAll('[name="key-mode"]').forEach(input => {
  input.onchange = () => {
    const upload = input.form.elements["key-mode"].value === "upload";
    byId("issuer-key").disabled = !upload;
    byId("key-state").textContent = upload ? "Select a private key file" : "Key generated on submit";
    if (upload) byId("issuer-key").focus();
  };
});
byId("issuer-key").onchange = () => byId("key-state").textContent = byId("issuer-key").files[0]?.name || "Select a private key";
byId("reset").onclick = () => {
  for (const [id, value] of Object.entries(defaults)) byId(id === "patchDate" ? "patch-date" : id).value = value;
  document.querySelector('[name="key-mode"][value="generate"]').checked = true;
  byId("issuer-key").value = "";
  byId("issuer-key").disabled = true;
  byId("key-state").textContent = "Key generated on submit";
  byId("confirmation").hidden = true;
  byId("error").textContent = "";
  artifacts = {};
  status("idle", "Ready to submit", "No submission in progress");
};
byId("download-redacted").onclick = () => download(artifacts.redacted, "redacted-statement.cose");
byId("download-full").onclick = () => download(artifacts.full, "authority-transparent-statement.cose");
byId("session-id").textContent = `Session ${session.slice(0, 8)}`;
byId("launcher-link").href = sessionUrl("index.html");
byId("next-link").href = sessionUrl("authority.html");
subscribe(session, event => {
  if (event.type === "reset" && event.detail.nextSession) {
    location.search = `?session=${encodeURIComponent(event.detail.nextSession)}`;
  }
});

publicConfiguration(session)
  .then(value => configuration = value)
  .catch(error => byId("error").textContent = error.message);
lucide.createIcons();
