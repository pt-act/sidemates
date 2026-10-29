import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import http from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { OpenBotDatabase } from "./database.js";
import { writeWorkspaceFile, replaceWorkspaceFile } from "./workspace-files.js";
import { safeHostEnvironment } from "./runtime.js";
import { buildRawEmail, decodeWorkThread, GoogleWorkspaceConnector } from "./google-workspace.js";
import { DevicePairing } from "./device-pairing.js";
import { OpenCodeRunner } from "./opencode.js";
import { AttachmentService } from "./attachments.js";

// Regression coverage for the seven hardening fixes: the owner credential
// replaces loopback trust, model-written runtime config is not data, Claude
// Code loads project settings only, the data home is owner-only, the model
// child cannot reach the SSH agent, invisible characters cannot spoof a
// recipient, and a deposed runner loses its authority.

const mode = (file: string) => Number(statSync(file).mode & 0o777);

function tempRoot(prefix: string) {
  return mkdtempSync(path.join(tmpdir(), `sidemates-${prefix}-`));
}

function database(root: string) {
  return new OpenBotDatabase(root, { dataDir: path.join(root, "data") });
}

function botFor(db: OpenBotDatabase, name: string) {
  return db.createBot({
    name, emoji: "T", color: "#3344aa", role: "Analyst", instructions: "Test teammate.",
    providerInstanceId: "local-opencode", model: "opencode/fixture", computerEnabled: false,
  });
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const socket = createServer();
    socket.listen(0, "127.0.0.1", () => {
      const port = (socket.address() as { port: number }).port;
      socket.close(() => resolve(port));
    });
  });
}

function request(port: number, method: string, route: string, headers: Record<string, string> = {}, body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const outgoing = http.request({ host: "127.0.0.1", port, method, path: route, headers }, (response) => {
      let data = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { data += chunk; });
      response.on("end", () => resolve({ status: response.statusCode || 0, body: data }));
    });
    outgoing.on("error", reject);
    if (body !== undefined) outgoing.write(body);
    outgoing.end();
  });
}

test("loopback without the owner credential cannot reach the studio API", { timeout: 120_000 }, async () => {
  const root = tempRoot("loopback");
  const dataDir = path.join(root, "data");
  const port = await freePort();
  const child = spawn(process.execPath, ["--import", "tsx", "src/server/index.ts"], {
    cwd: path.resolve(import.meta.dirname, "../.."),
    env: {
      ...process.env,
      OPENBOT_LOAD_ENV: "0", OPENBOT_UPDATE_CHECK: "0",
      OPENBOT_DATA_DIR: dataDir, OPENBOT_PORT: String(port), OPENBOT_HOST: "127.0.0.1",
      OPENBOT_APP_URL: `http://127.0.0.1:${port}`, OPENBOT_DEPLOYMENT_MODE: "local",
      NODE_ENV: "production", OPENBOT_STAGING: "1", OPENBOT_OPENCODE_VERSION: "1.18.31",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { log = (log + String(chunk)).slice(-3000); });
  const exited = once(child, "exit");
  try {
    let ready = false;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      try { ready = (await request(port, "GET", "/api/healthz")).status === 200; } catch { /* starting */ }
      if (ready || child.exitCode !== null) break;
      await delay(100);
    }
    assert.ok(ready, `server did not start: ${log}`);

    let token = "";
    for (let attempt = 0; attempt < 100 && !token; attempt += 1) {
      const file = path.join(dataDir, "access.token");
      if (existsSync(file)) token = readFileSync(file, "utf8").trim();
      if (!token) await delay(50);
    }
    assert.ok(token, `token file was not written: ${log}`);

    assert.equal((await request(port, "GET", "/api/healthz")).status, 200, "health stays public");
    assert.equal((await request(port, "GET", "/api/access")).status, 401, "unauthenticated loopback read the access key");
    assert.equal((await request(port, "GET", "/api/state")).status, 401, "unauthenticated loopback read studio state");
    assert.equal((await request(port, "PATCH", "/api/settings", { "content-type": "application/json" }, JSON.stringify({ yoloMode: true }))).status, 401, "unauthenticated loopback changed settings");

    const owner = await request(port, "GET", "/api/access", { authorization: `Bearer ${token}` });
    assert.equal(owner.status, 200, owner.body);
    assert.equal(JSON.parse(owner.body).token, token, "the owner still receives the access key");
    assert.equal((await request(port, "GET", "/api/access", { cookie: `openbot_access=${encodeURIComponent(token)}` })).status, 200, "the owner cookie still works");

    assert.equal((await request(port, "GET", "/api/access", { authorization: `Bearer ${token}`, host: "evil.example" })).status, 403, "a non-loopback Host reached the access key");
    assert.equal((await request(port, "GET", "/api/access", { authorization: `Bearer ${token}`, origin: "https://evil.example" })).status, 403, "a cross-site Origin reached the access key");

    const forged = await request(port, "POST", "/api/internal/tools", { "content-type": "application/json", "x-openbot-token": "A".repeat(43) }, JSON.stringify({ botId: "bot", runId: "run", action: "workspace_list", args: {} }));
    assert.equal(forged.status, 403, "a forged scoped tool token was accepted");
    const none = await request(port, "POST", "/api/internal/tools", { "content-type": "application/json" }, JSON.stringify({ botId: "bot", runId: "run", action: "workspace_list", args: {} }));
    assert.equal(none.status, 401, "the tool bridge was reachable without a credential");
  } finally {
    child.kill("SIGTERM");
    await Promise.race([exited, delay(4000)]);
    if (child.exitCode === null) { child.kill("SIGKILL"); await exited; }
    rmSync(root, { recursive: true, force: true });
  }
});

test("the data home, database and sidecars are owner-only", { timeout: 60_000 }, async () => {
  const root = tempRoot("permissions");
  const db = database(root);
  try {
    for (const directory of [db.dataDir, db.workspacesDir, db.computersDir, db.attachmentsDir, path.join(db.dataDir, "keys")]) {
      assert.equal(mode(directory), 0o700, `${directory} is ${mode(directory).toString(8)}`);
    }
    assert.equal(mode(path.join(db.dataDir, "keys", "vault.key")), 0o600);
    botFor(db, "Permissions");
    const databasePath = path.join(db.dataDir, "openbot.sqlite");
    for (const file of [databasePath, `${databasePath}-wal`, `${databasePath}-shm`]) {
      if (existsSync(file)) assert.equal(mode(file), 0o600, `${file} is ${mode(file).toString(8)}`);
    }
    const pairing = new DevicePairing(path.join(db.dataDir, "paired-devices.sqlite"));
    assert.equal(mode(path.join(db.dataDir, "paired-devices.sqlite")), 0o600);
    pairing.close();
  } finally {
    db.close();
    rmSync(root, { recursive: true, force: true });
  }

  const looseRoot = tempRoot("permissions-loose");
  try {
    const dataPath = path.join(looseRoot, "data");
    mkdirSync(dataPath, { recursive: true, mode: 0o777 });
    chmodSync(dataPath, 0o777);
    const first = database(looseRoot);
    first.close();
    const databasePath = path.join(dataPath, "openbot.sqlite");
    chmodSync(dataPath, 0o777);
    chmodSync(databasePath, 0o666);
    const second = database(looseRoot);
    try {
      assert.equal(mode(dataPath), 0o700, "a pre-existing permissive data home was not tightened");
      assert.equal(mode(databasePath), 0o600, "a pre-existing permissive database was not tightened");
    } finally {
      second.close();
    }
  } finally {
    rmSync(looseRoot, { recursive: true, force: true });
  }
});

test("model-written runtime configuration is not a workspace write", { timeout: 60_000 }, async () => {
  const root = tempRoot("workspace");
  try {
    const reserved = [
      ".opencode/tools/escape.ts", ".opencode/plugins/escape.js", ".opencode/opencode.json", ".opencode/skills/x/SKILL.md",
      ".claude/settings.local.json", ".claude/settings.json", ".claude/hooks/run.sh",
      ".OPENCODE/tools/escape.ts", ".Claude/settings.local.json", "./.opencode/tools/escape.ts",
      "sub/../.opencode/tools/escape.ts", "opencode.json", "CLAUDE.md", "AGENTS.md", ".mcp.json", "OPENCODE.JSON", ".opencode", ".claude",
    ];
    for (const relative of reserved) {
      const written = await writeWorkspaceFile(root, relative, "malicious");
      assert.equal(written.ok, false, `write unexpectedly allowed: ${relative}`);
      if (!written.ok) assert.equal(written.reason, "reserved_runtime_path", `${relative} -> ${written.reason}`);
    }

    mkdirSync(path.join(root, ".opencode/tools"), { recursive: true });
    writeFileSync(path.join(root, ".opencode/tools/existing.ts"), "one");
    for (const relative of [".opencode/tools/existing.ts", ".claude/settings.local.json", "CLAUDE.md", ".mcp.json"]) {
      const replaced = await replaceWorkspaceFile(root, relative, "one", "two");
      assert.equal(replaced.ok, false, `replace unexpectedly allowed: ${relative}`);
      if (!replaced.ok) assert.equal(replaced.reason, "reserved_runtime_path", `${relative} -> ${replaced.reason}`);
    }
    assert.equal(readFileSync(path.join(root, ".opencode/tools/existing.ts"), "utf8"), "one");

    for (const relative of ["data.txt", "notes/CLAUDE.md", "tools/poc_fires.ts", "dir/AGENTS.md", ".data/state.json"]) {
      const written = await writeWorkspaceFile(root, relative, "ordinary");
      assert.equal(written.ok, true, `${relative} -> ${written.ok ? "ok" : written.reason}`);
      assert.equal(readFileSync(path.join(root, relative), "utf8"), "ordinary");
    }

    symlinkSync(path.join(root, ".opencode"), path.join(root, "alias"), "dir");
    const alias = await writeWorkspaceFile(root, "alias/tools/escape.ts", "malicious");
    assert.equal(alias.ok, false, "a symlink alias to .opencode was writable");
    assert.equal(existsSync(path.join(root, ".opencode/tools/escape.ts")), false);
    assert.equal((await writeWorkspaceFile(root, "../outside.txt", "malicious")).ok, false, "traversal was allowed");

    const fresh = tempRoot("workspace-fresh");
    try {
      assert.equal((await writeWorkspaceFile(fresh, ".opencode/tools/escape.ts", "malicious")).ok, false);
      assert.equal(existsSync(path.join(fresh, ".opencode")), false, "a refused write created the reserved directory");
    } finally {
      rmSync(fresh, { recursive: true, force: true });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the model child environment cannot reach the owner's SSH agent", { timeout: 30_000 }, async () => {
  const env = safeHostEnvironment({ OPENBOT_RUN_ID: "run-1" }, {
    PATH: "/usr/bin:/bin", HOME: "/tmp/home", USER: "owner", LANG: "en_US.UTF-8",
    SSH_AUTH_SOCK: "/tmp/agent.sock", SSH_ASKPASS: "/tmp/askpass", GIT_ASKPASS: "/tmp/git-askpass", GIT_SSH_COMMAND: "evil",
    GPG_AGENT_INFO: "/tmp/gpg", AWS_SECRET_ACCESS_KEY: "aws", GITHUB_TOKEN: "gh", GH_TOKEN: "gh2",
  });
  for (const key of ["SSH_AUTH_SOCK", "SSH_ASKPASS", "GIT_ASKPASS", "GIT_SSH_COMMAND", "GPG_AGENT_INFO", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GH_TOKEN"]) {
    assert.equal(key in env, false, `${key} leaked into the model child environment`);
  }
  assert.equal(env.HOME, "/tmp/home");
  assert.equal(env.USER, "owner");
  assert.ok(env.PATH?.includes("/usr/bin"));
  assert.equal(env.OPENBOT_RUN_ID, "run-1");
});

test("Claude Code loads project settings only", { timeout: 30_000 }, async () => {
  const source = readFileSync(path.resolve(import.meta.dirname, "opencode.ts"), "utf8");
  assert.ok(source.includes('"--setting-sources", "project"'), "the launch args do not pin the project setting source");
  assert.ok(!source.includes('"project,local"'), "the owner's local settings are still loaded");
});

test("invisible characters cannot spoof an address or calendar attendee", { timeout: 60_000 }, async () => {
  const payloads = ["\u202e", "\u202a", "\u2066", "\u2069", "\u200e", "\u200f", "\u200c", "\u200d"];
  for (const payload of payloads) {
    for (const address of [`attacker@evil.example${payload}`, `${payload}attacker@evil.example`, `attacker${payload}@evil.example`]) {
      assert.throws(() => buildRawEmail({ to: address, subject: "s", body: "b" }), `accepted a To address with U+${payload.codePointAt(0)!.toString(16)}`);
      assert.throws(() => buildRawEmail({ to: "ok@example.com", cc: address, subject: "s", body: "b" }), `accepted a Cc address with U+${payload.codePointAt(0)!.toString(16)}`);
    }
  }
  for (const control of ["\u0000", "\u0001", "\u001f", "\u007f", "\u009f"]) {
    assert.throws(() => buildRawEmail({ to: `attacker@evil.example${control}`, subject: "s", body: "b" }), `accepted a control U+${control.codePointAt(0)!.toString(16)}`);
  }
  assert.throws(() => buildRawEmail({ to: "a@b.co\r\nBcc: evil@x.co", subject: "s", body: "b" }), "header injection was accepted");

  // trim() removes edge whitespace, including a BOM or trailing CR/LF, so the
  // clean address is what ships. Nothing invisible may reach the header.
  for (const to of ["\uFEFFattacker@evil.example", "attacker@evil.example\uFEFF", "attacker@evil.example\r", "attacker@evil.example\n", "attacker@evil.example\t"]) {
    const text = Buffer.from(buildRawEmail({ to, subject: "s", body: "b" }), "base64url").toString("utf8");
    const toLine = text.split("\r\n").find((line) => line.startsWith("To: "))!;
    assert.equal(toLine, "To: attacker@evil.example", "an edge character altered the delivered address");
  }

  for (const to of ["josé@example.com", "first.last+tag@example.co.uk", "a@b.co, c@d.io"]) {
    const text = Buffer.from(buildRawEmail({ to, cc: "x@y.z, q@r.st", subject: "Hello", body: "Body" }), "base64url").toString("utf8");
    assert.ok(text.includes("To: ") && text.includes("Cc: "), "a legitimate address was rejected");
    assert.ok(!text.includes("\u202e"));
  }

  const root = tempRoot("mail");
  const db = database(root);
  try {
    let networkCalls = 0;
    const connector = new GoogleWorkspaceConnector(db, "http://127.0.0.1/callback", (async () => {
      networkCalls += 1;
      throw new Error("NETWORK_SENTINEL");
    }) as unknown as typeof fetch);
    const start = new Date(Date.now() + 60_000).toISOString();
    const end = new Date(Date.now() + 3_600_000).toISOString();
    await assert.rejects(connector.createCalendarEvent({ title: "T", start, end, attendees: ["attacker@evil.example\u202e"] }), /valid attendee/);
    assert.equal(networkCalls, 0, "attendee validation did not run before the network call");
    const legit = await connector.createCalendarEvent({ title: "T", start, end, attendees: ["good@example.com"] }).then(() => null, (error: Error) => error);
    assert.ok(legit && !/valid attendee/.test(legit.message), "a legitimate attendee was rejected");

    const payload = {
      mimeType: "text/plain", body: { data: Buffer.from("hello").toString("base64url") },
      headers: [{ name: "Reply-To", value: "attacker@evil.example\u202e" }, { name: "From", value: "sender@example.com" }],
    };
    const messages = [{ id: "m1", internalDate: "1700000000000", labelIds: ["INBOX"], payload }] as unknown as Parameters<typeof decodeWorkThread>[1];
    assert.equal(decodeWorkThread("thread-1", messages).replyTo, null, "a bidi Reply-To was offered as a reply address");
    const legitPayload = { ...payload, headers: [{ name: "Reply-To", value: "reply@example.com" }] };
    const legitMessages = [{ id: "m2", internalDate: "1700000000000", labelIds: ["INBOX"], payload: legitPayload }] as unknown as Parameters<typeof decodeWorkThread>[1];
    assert.equal(decodeWorkThread("thread-2", legitMessages).replyTo, "reply@example.com");
  } finally {
    db.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("a deposed runner loses tool authority and its live children", { timeout: 60_000 }, async () => {
  const root = tempRoot("leases");
  const db = database(root);
  try {
    const bot = botFor(db, "Lease");
    const newRun = () => db.createRun({ threadId: bot.threadId, botId: bot.id, prompt: "work", status: "queued" });

    assert.ok(db.acquireRunnerLease("worker-a", "foreground"));
    const live = newRun();
    assert.equal(db.claimNextQueuedRun([], "worker-a", 60_000)?.id, live.id);
    assert.equal(db.ownsRunLease(live.id, "worker-a"), true);
    assert.equal(db.ownsRunLease(live.id, "worker-b"), false);

    const lapsed = newRun();
    assert.equal(db.claimNextQueuedRun([], "worker-a", 60_000)?.id, lapsed.id);
    db.renewRunLeases("worker-a", 25);
    await delay(70);
    assert.equal(db.ownsRunLease(lapsed.id, "worker-a"), false, "a lapsed lease kept its authority");

    const finished = newRun();
    assert.equal(db.claimNextQueuedRun([], "worker-a", 60_000)?.id, finished.id);
    db.updateRun(finished.id, { status: "completed" });
    assert.equal(db.ownsRunLease(finished.id, "worker-a"), false, "a finished run kept its authority");

    const takeoverRoot = tempRoot("takeover");
    const takeover = database(takeoverRoot);
    try {
      const takeoverBot = botFor(takeover, "Takeover");
      assert.ok(takeover.acquireRunnerLease("worker-a", "foreground"));
      const run = takeover.createRun({ threadId: takeoverBot.threadId, botId: takeoverBot.id, prompt: "work", status: "queued" });
      assert.equal(takeover.claimNextQueuedRun([], "worker-a", 60_000)?.id, run.id);
      assert.equal(takeover.requeueWorkerRuns("worker-a"), 1);
      assert.equal(takeover.ownsRunLease(run.id, "worker-a"), false);
      assert.equal(takeover.claimNextQueuedRun([], "worker-b", 60_000)?.id, run.id);
      assert.equal(takeover.ownsRunLease(run.id, "worker-b"), true);
      assert.equal(takeover.ownsRunLease(run.id, "worker-a"), false);
    } finally {
      takeover.close();
      rmSync(takeoverRoot, { recursive: true, force: true });
    }
  } finally {
    db.close();
    rmSync(root, { recursive: true, force: true });
  }

  const runnerRoot = tempRoot("depose");
  const runnerDb = database(runnerRoot);
  try {
    let acquire = true;
    const requeued: string[] = [];
    const originalRequeue = runnerDb.requeueWorkerRuns.bind(runnerDb);
    (runnerDb as unknown as { requeueWorkerRuns: (workerId: string) => number }).requeueWorkerRuns = (workerId: string) => {
      requeued.push(workerId);
      return originalRequeue(workerId);
    };
    (runnerDb as unknown as { acquireRunnerLease: () => boolean }).acquireRunnerLease = () => acquire;
    const runner = new OpenCodeRunner({
      db: runnerDb, onChange: () => {}, internalUrl: "http://127.0.0.1:1", internalToken: "fixture",
      runtimeCheck: () => ({ runtime: "opencode" as const, detectedVersion: "1.18.31", compatibility: "verified" as const }),
      attachments: new AttachmentService(runnerDb),
    });
    (runner as unknown as { leader: boolean }).leader = true;
    let checkpointed = 0, terminated = 0;
    (runner as unknown as { running: Map<string, unknown> }).running.set("run-1", { once: () => undefined });
    (runner as unknown as { processControls: Map<string, { checkpoint: () => void; terminate: () => void }> }).processControls.set("run-1", {
      checkpoint: () => { checkpointed += 1; },
      terminate: () => { terminated += 1; },
    });
    acquire = false;
    (runner as unknown as { maintainLeadership: () => void }).maintainLeadership();
    assert.equal(runner.isLeader(), false);
    assert.equal(checkpointed, 1, "the deposed runner did not checkpoint its child");
    assert.equal(terminated, 1, "the deposed runner did not terminate its child");
    assert.ok(requeued.includes(runner.instanceId), "the deposed runner did not requeue its runs");
  } finally {
    runnerDb.close();
    rmSync(runnerRoot, { recursive: true, force: true });
  }
});
