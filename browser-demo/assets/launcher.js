import {
  getSession,
  listDeliveries,
  listDisclosures,
  resetSession,
  setSession,
  subscribe,
} from "./simulator.js";

const session = getSession();
const byId = id => document.getElementById(id);
const roleUrls = ["researcher.html", "authority.html", "verifier.html"];
const sessionUrl = path => `${path}?session=${encodeURIComponent(session)}`;

async function refreshCounts() {
  const [deliveries, disclosures] = await Promise.all([
    listDeliveries(session),
    listDisclosures(session),
  ]);
  byId("delivery-count").textContent = deliveries.length;
  byId("disclosure-count").textContent = disclosures.length;
}

byId("session-id").textContent = session;
for (const [role, path] of [["researcher", roleUrls[0]], ["authority", roleUrls[1]], ["verifier", roleUrls[2]]]) {
  byId(`${role}-link`).href = sessionUrl(path);
}

byId("open-all").onclick = () => {
  const opened = roleUrls.map((path, index) => window.open(sessionUrl(path), `evld-${session}-${index}`));
  if (opened.some(tab => !tab)) {
    byId("message").textContent = "Your browser blocked one or more tabs. Use the individual role links instead.";
  }
};

byId("reset").onclick = async () => {
  byId("reset").disabled = true;
  byId("message").textContent = "";
  try {
    const next = crypto.randomUUID();
    await resetSession(session, next);
    setSession(next);
    location.search = `?session=${encodeURIComponent(next)}`;
  } catch (error) {
    byId("message").textContent = error.message;
    byId("reset").disabled = false;
  }
};

subscribe(session, refreshCounts);
refreshCounts().catch(error => byId("message").textContent = error.message);
lucide.createIcons();
