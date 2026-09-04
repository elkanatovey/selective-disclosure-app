const [debugOrigin = "http://127.0.0.1:9222", targetPath = "/browser-demo/tests/"] = process.argv.slice(2);
const deadline = Date.now() + 30_000;
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function findTarget() {
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${debugOrigin}/json/list`);
      if (response.ok) {
        const targets = await response.json();
        const target = targets.find(candidate => candidate.type === "page" && candidate.url.includes(targetPath));
        if (target) return target;
      }
    } catch {
      // Chrome may not have opened its debugging endpoint yet.
    }
    await delay(250);
  }
  throw new Error(`Chrome did not expose ${targetPath}`);
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.addEventListener("open", () => resolve(socket), {once: true});
    socket.addEventListener("error", () => reject(new Error("Could not connect to Chrome")), {once: true});
  });
}

function client(socket) {
  let nextId = 1;
  const pending = new Map();
  socket.addEventListener("message", event => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const {resolve, reject} = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(message.error.message));
    else resolve(message.result);
  });
  return (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, {resolve, reject});
    socket.send(JSON.stringify({id, method, params}));
  });
}

const target = await findTarget();
const socket = await connect(target.webSocketDebuggerUrl);
const send = client(socket);
let lastResult;

try {
  await send("Runtime.enable");
  while (Date.now() < deadline) {
    const evaluation = await send("Runtime.evaluate", {
      expression: `({
        state: document.body?.dataset.state,
        result: document.getElementById("result")?.textContent
      })`,
      returnByValue: true,
    });
    lastResult = evaluation.result.value;
    if (lastResult?.state === "passed") {
      console.log(lastResult.result);
      process.exitCode = 0;
      break;
    }
    if (lastResult?.state === "failed") {
      throw new Error(lastResult.result || "Browser self-test failed");
    }
    await delay(250);
  }
  if (lastResult?.state !== "passed") {
    throw new Error(`Browser self-test timed out: ${JSON.stringify(lastResult)}`);
  }
} finally {
  socket.close();
}
