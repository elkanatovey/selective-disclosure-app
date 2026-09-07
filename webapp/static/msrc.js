import { b64 } from "./cbor.js";
import { ReviewModel } from "./review-model.js";
import { BODY_CHUNK_SIZE, inspectStatement } from "./report-profile.js";
const $ = (id) => document.getElementById(id);
const review = new ReviewModel();
let bodyPaint;
async function inspect(statement) {
  const response = await fetch("/api/inspect", {
      method: "POST",
      headers: { "content-type": "application/cose" },
      body: statement,
    }),
    data = await response.json();
  if (!response.ok) throw new Error(data.detail || response.statusText);
  return data;
}
async function sign(statement, selected, audience) {
  const response = await fetch("/api/disclosures", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ statement: b64(statement), selected: selected.map(b64), audience }),
  });
  if (!response.ok) {
    const data = await response.json();
    throw new Error(data.detail || response.statusText);
  }
  return new Uint8Array(await response.arrayBuffer());
}
const hex = (bytes) => [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
function display(field) {
  if (field.value instanceof Uint8Array)
    return field.type === "hex" ? hex(field.value) : "Not provided";
  if (field.name === "patch_date" && Number.isInteger(field.value))
    return new Date(field.value * 1000).toISOString().slice(0, 10);
  return String(field.value);
}
function status(state, title, detail) {
  $("sign-status").dataset.state = state;
  $("sign-title").textContent = title;
  $("sign-detail").textContent = detail;
}
function update() {
  for (const input of document.querySelectorAll("[data-choice]")) {
    input.checked = review.selected.has(input.dataset.choice);
  }
  $("body-all").checked = review.allSelected("body");
  $("references-all").checked = review.allSelected("reference");
  const count = review.selected.size;
  $("selection-count").textContent = `${count} item${count === 1 ? "" : "s"} selected`;
  $("sign").disabled = !review.canSign;
  $("export").disabled = !review.canExport;
  $("sign-error").textContent = review.error;
  $("kbt-size").textContent = review.canExport
    ? `${review.token.length.toLocaleString()} B`
    : review.phase === "signing"
      ? "Signing"
      : "Not signed";
  if (review.phase === "signing")
    status("working", "Signing disclosure", "Creating Key Binding Token");
  else if (review.canExport)
    status("success", "Disclosure signed", `Verified against ${review.verified.txid}`);
  else if (review.error) status("error", "Signing failed", "No token was created");
  else status("idle", "Ready to sign", "KBT uses the key bound in cnf");
}

function selectionInput(choice) {
  const input = document.createElement("input");
  input.type = "checkbox";
  input.dataset.choice = choice.id;
  input.disabled = choice.disabled;
  input.onchange = () => {
    review.setSelected(choice.id, input.checked);
    update();
  };
  return input;
}

function checkbox(choice) {
  const row = document.createElement("div");
  row.className = `field-row${choice.disabled ? " absent" : ""}`;
  const name = document.createElement("label");
  name.textContent = choice.label;
  const value = display(choice);
  const content = document.createElement(value.length > 80 ? "span" : "code");
  content.textContent = value;
  row.append(selectionInput(choice), name, content);
  return row;
}
function paintBody(id, value) {
  review.setSelected(id, value);
  update();
}
function render() {
  $("field-list").replaceChildren();
  for (const choice of review.choices.filter((choice) => choice.kind === "field")) {
    $("field-list").append(checkbox(choice));
  }
  const body = review.choices.filter((choice) => choice.kind === "body");
  $("body-review").hidden = !body.length;
  $("body-chunks").replaceChildren();
  for (const choice of body) {
    const label = document.createElement("label");
    label.className = "chunk";
    const input = selectionInput(choice);
    input.onkeydown = (event) => {
      if (event.key === " ") {
        event.preventDefault();
        paintBody(choice.id, !review.selected.has(choice.id));
      }
    };
    label.onclick = (event) => event.preventDefault();
    label.onpointerdown = (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      bodyPaint = !review.selected.has(choice.id);
      $("body-chunks").classList.add("dragging");
      paintBody(choice.id, bodyPaint);
    };
    label.onpointerenter = (event) => {
      if (bodyPaint !== undefined && event.buttons & 1) paintBody(choice.id, bodyPaint);
    };
    const span = document.createElement("span");
    span.textContent = choice.value;
    label.append(input, span);
    $("body-chunks").append(label);
  }
  $("body-count").textContent = `${body.length} × ${BODY_CHUNK_SIZE}-character chunks`;
  const refs = review.choices.filter((choice) => choice.kind === "reference");
  $("reference-review").hidden = !refs.length;
  $("reference-list").replaceChildren();
  for (const choice of refs) {
    const label = document.createElement("label");
    label.className = "reference-option";
    label.append(selectionInput(choice), document.createTextNode(choice.value));
    $("reference-list").append(label);
  }
  update();
}
async function load(file) {
  if (!file) return;
  $("load-error").textContent = "";
  $("review").hidden = true;
  $("import-view").hidden = false;
  const loaded = await review.load(async () => {
    const statement = new Uint8Array(await file.arrayBuffer());
    const verified = await inspect(statement);
    if (!verified.receiptVerified) throw new Error("SCITT receipt was not verified");
    return { report: await inspectStatement(statement), verified };
  });
  if (!loaded) {
    if (!review.report) $("load-error").textContent = review.error;
    return;
  }
  $("report-subject").textContent = review.verified.subject || file.name;
  $("report-txid").textContent = review.verified.txid;
  render();
  $("import-view").hidden = true;
  $("review").hidden = false;
  lucide.createIcons();
}
$("statement-file").onchange = (event) =>
  load(event.target.files[0]).catch((error) => ($("load-error").textContent = error.message));
for (const event of ["pointerup", "pointercancel"])
  window.addEventListener(event, () => {
    bodyPaint = undefined;
    $("body-chunks").classList.remove("dragging");
  });
for (const event of ["dragenter", "dragover"])
  $("drop-zone").addEventListener(event, () => $("drop-zone").classList.add("dragging"));
for (const event of ["dragleave", "drop"])
  $("drop-zone").addEventListener(event, () => $("drop-zone").classList.remove("dragging"));
$("drop-zone").ondrop = (event) => {
  event.preventDefault();
  load(event.dataTransfer.files[0]).catch((error) => ($("load-error").textContent = error.message));
};
$("drop-zone").ondragover = (event) => event.preventDefault();
$("select-all").onclick = () => {
  review.selectAll(true);
  update();
};
$("clear-all").onclick = () => {
  review.selectAll(false);
  update();
};
for (const [master, kind] of [
  ["body-all", "body"],
  ["references-all", "reference"],
])
  $(master).onchange = (event) => {
    review.selectAll(event.target.checked, kind);
    update();
  };
$("audience").oninput = () => {
  review.setAudience($("audience").value);
  update();
};
$("sign").onclick = async () => {
  const signing = review.sign(sign);
  update();
  await signing;
  update();
};
$("export").onclick = () => {
  if (!review.canExport) return;
  const url = URL.createObjectURL(new Blob([review.token], { type: "application/kb+cwt" })),
    link = document.createElement("a");
  link.href = url;
  link.download = `disclosure-${review.verified.txid}.kbt.cose`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
};
review.setAudience($("audience").value);
update();
lucide.createIcons();
