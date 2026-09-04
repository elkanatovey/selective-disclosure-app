import {
  createDisclosure,
  getSession,
  inspectDelivery,
  listDeliveries,
  subscribe,
} from "./simulator.js";

const byId = id => document.getElementById(id);
const names = {1001: "Title", 1003: "Component", 1004: "Severity", 1005: "Fingerprint", 1007: "Patch", 1008: "Patch date"};
const session = getSession();
let activeTxid;
let model;
let verified;
let kbt;
let choices = [];
let bodyPaint;

const sessionUrl = path => `${path}?session=${encodeURIComponent(session)}`;
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, "0")).join("");

function display(field) {
  if (field.value instanceof Uint8Array) return field.key === 1005 ? hex(field.value) : "Not provided";
  if (field.key === 1008 && Number.isInteger(field.value)) return new Date(field.value * 1000).toISOString().slice(0, 10);
  return String(field.value);
}

function status(state, title, detail) {
  byId("sign-status").dataset.state = state;
  byId("sign-title").textContent = title;
  byId("sign-detail").textContent = detail;
}

function updateCount() {
  const selected = choices.filter(choice => choice.input.checked).length;
  byId("selection-count").textContent = `${selected} item${selected === 1 ? "" : "s"} selected`;
}

function invalidate() {
  kbt = undefined;
  byId("export").disabled = true;
  byId("kbt-size").textContent = "Not signed";
  status("idle", "Ready to sign", "KBT uses the authority key bound in cnf");
  updateCount();
}

function checkbox(choice, label, value, absent = false) {
  const row = document.createElement("div");
  row.className = `field-row${absent ? " absent" : ""}`;
  const input = document.createElement("input");
  input.type = "checkbox";
  input.checked = !absent;
  input.disabled = absent;
  input.onchange = invalidate;
  choice.input = input;
  choices.push(choice);
  const name = document.createElement("label");
  name.textContent = label;
  const content = document.createElement(value.length > 80 ? "span" : "code");
  content.textContent = value;
  row.append(input, name, content);
  return row;
}

function paintBody(body, child, value) {
  if (child.input.checked === value) return;
  child.input.checked = value;
  byId("body-all").checked = body.children.every(item => item.input.checked);
  invalidate();
}

function render() {
  choices = [];
  byId("field-list").replaceChildren();
  for (const key of [1001, 1003, 1004, 1005, 1007, 1008]) {
    const field = model.fields.get(key);
    const absent = field.value instanceof Uint8Array && key !== 1005;
    byId("field-list").append(checkbox({kind: "field", field}, names[key], display(field), absent));
  }
  const body = model.fields.get(1002);
  byId("body-review").hidden = !body.children.length;
  byId("body-chunks").replaceChildren();
  for (const child of body.children) {
    const label = document.createElement("label");
    label.className = "chunk";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = true;
    input.onchange = () => {
      byId("body-all").checked = body.children.every(item => item.input.checked);
      invalidate();
    };
    input.onkeydown = event => {
      if (event.key === " ") {
        event.preventDefault();
        paintBody(body, child, !input.checked);
      }
    };
    label.onclick = event => event.preventDefault();
    label.onpointerdown = event => {
      if (event.button !== 0) return;
      event.preventDefault();
      bodyPaint = !input.checked;
      byId("body-chunks").classList.add("dragging");
      paintBody(body, child, bodyPaint);
    };
    label.onpointerenter = event => {
      if (bodyPaint !== undefined && event.buttons & 1) paintBody(body, child, bodyPaint);
    };
    child.input = input;
    choices.push({kind: "body", field: body, child, input});
    const span = document.createElement("span");
    span.textContent = child.value;
    label.append(input, span);
    byId("body-chunks").append(label);
  }
  byId("body-count").textContent = `${body.children.length} × 6-character chunks`;

  const references = model.fields.get(1006);
  byId("reference-review").hidden = !references.children.length;
  byId("reference-list").replaceChildren();
  for (const child of references.children) {
    const label = document.createElement("label");
    label.className = "reference-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = true;
    input.onchange = () => {
      byId("references-all").checked = references.children.every(item => item.input.checked);
      invalidate();
    };
    child.input = input;
    choices.push({kind: "reference", field: references, child, input});
    label.append(input, document.createTextNode(child.value));
    byId("reference-list").append(label);
  }
  updateCount();
}

function selectedOpenings() {
  const selected = [];
  const parents = new Set();
  for (const choice of choices.filter(item => item.input.checked)) {
    if (choice.kind === "field") {
      selected.push(choice.field.opening);
    } else {
      if (!parents.has(choice.field.key)) {
        selected.push(choice.field.opening);
        parents.add(choice.field.key);
      }
      selected.push(choice.child.opening);
    }
  }
  return selected;
}

async function load(txid) {
  byId("load-error").textContent = "";
  const inspected = await inspectDelivery(session, txid);
  activeTxid = txid;
  verified = inspected;
  model = inspected.model;
  byId("report-subject").textContent = inspected.verified.subject;
  byId("report-txid").textContent = inspected.receipt.txid;
  render();
  byId("import-view").hidden = true;
  byId("review").hidden = false;
  lucide.createIcons();
}

async function refreshDeliveries(autoOpen = false) {
  const deliveries = await listDeliveries(session);
  byId("delivery-list").replaceChildren();
  if (!deliveries.length) {
    const empty = document.createElement("div");
    empty.className = "available-empty";
    empty.textContent = "Waiting for a Researcher tab to submit a report";
    byId("delivery-list").append(empty);
    return;
  }
  for (const delivery of deliveries) {
    const item = document.createElement("div");
    item.className = "available-item";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = delivery.subject;
    const detail = document.createElement("small");
    detail.textContent = `${delivery.txid} · ${new Date(delivery.deliveredAt).toLocaleTimeString()}`;
    copy.append(title, detail);
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Review";
    button.onclick = () => load(delivery.txid).catch(error => byId("load-error").textContent = error.message);
    item.append(copy, button);
    byId("delivery-list").append(item);
  }
  if (autoOpen && byId("review").hidden) await load(deliveries[0].txid);
}

for (const event of ["pointerup", "pointercancel"]) window.addEventListener(event, () => {
  bodyPaint = undefined;
  byId("body-chunks").classList.remove("dragging");
});
byId("select-all").onclick = () => {
  for (const choice of choices) if (!choice.input.disabled) choice.input.checked = true;
  byId("body-all").checked = true;
  byId("references-all").checked = true;
  invalidate();
};
byId("clear-all").onclick = () => {
  for (const choice of choices) choice.input.checked = false;
  byId("body-all").checked = false;
  byId("references-all").checked = false;
  invalidate();
};
for (const [master, kind] of [["body-all", "body"], ["references-all", "reference"]]) {
  byId(master).onchange = event => {
    for (const choice of choices.filter(item => item.kind === kind)) choice.input.checked = event.target.checked;
    invalidate();
  };
}
byId("audience").oninput = invalidate;
byId("sign").onclick = async () => {
  try {
    byId("sign").disabled = true;
    byId("export").disabled = true;
    byId("kbt-size").textContent = "Signing";
    byId("sign-error").textContent = "";
    status("working", "Signing disclosure", "Creating audience-bound Key Binding Token");
    const result = await createDisclosure(session, activeTxid, selectedOpenings(), byId("audience").value);
    kbt = result.token;
    status("success", "Disclosure signed", `Verified against ${verified.receipt.txid}`);
    byId("kbt-size").textContent = `${kbt.length.toLocaleString()} B`;
    byId("export").disabled = false;
  } catch (error) {
    kbt = undefined;
    byId("kbt-size").textContent = "Not signed";
    byId("sign-error").textContent = error.message;
    status("error", "Signing failed", "No token was created");
  } finally {
    byId("sign").disabled = false;
  }
};
byId("export").onclick = () => {
  const url = URL.createObjectURL(new Blob([kbt], {type: "application/kb+cwt"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = `disclosure-${verified.receipt.txid}.kbt.cose`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
};
byId("back").onclick = () => {
  byId("review").hidden = true;
  byId("import-view").hidden = false;
  refreshDeliveries().catch(error => byId("load-error").textContent = error.message);
};
byId("session-id").textContent = `Session ${session.slice(0, 8)}`;
byId("launcher-link").href = sessionUrl("index.html");
byId("next-link").href = sessionUrl("verifier.html");
subscribe(session, event => {
  if (event.type === "report-delivered") refreshDeliveries(true).catch(error => byId("load-error").textContent = error.message);
  if (event.type === "reset" && event.detail.nextSession) location.search = `?session=${encodeURIComponent(event.detail.nextSession)}`;
});
refreshDeliveries().catch(error => byId("load-error").textContent = error.message);
lucide.createIcons();
