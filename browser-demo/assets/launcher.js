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
const roleNames = ["Researcher", "Authority", "Verifier"];
const sessionUrl = path => `${path}?session=${encodeURIComponent(session)}`;
let blockedRoles = [];

function openRole(index) {
  return window.open(sessionUrl(roleUrls[index]), `evld-${session}-${index}`);
}

function updateOpenNext() {
  const button = byId("open-next");
  button.hidden = blockedRoles.length === 0;
  if (blockedRoles.length) button.textContent = `Open ${roleNames[blockedRoles[0]]}`;
}

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
  byId("message").textContent = "";
  blockedRoles = roleUrls.map((_, index) => index).filter(index => !openRole(index));
  updateOpenNext();
  if (blockedRoles.length) {
    byId("message").textContent = "Pop-ups blocked. Allow pop-ups for this site and try again, or open the remaining roles one at a time.";
  }
};

byId("open-next").onclick = () => {
  const index = blockedRoles[0];
  if (index === undefined) return;
  if (!openRole(index)) {
    byId("message").textContent = "Pop-up blocked. Allow pop-ups for this site or use the role links below.";
    return;
  }
  blockedRoles.shift();
  updateOpenNext();
  byId("message").textContent = blockedRoles.length ? `${blockedRoles.length} role tab${blockedRoles.length === 1 ? "" : "s"} remaining.` : "All role tabs opened.";
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
