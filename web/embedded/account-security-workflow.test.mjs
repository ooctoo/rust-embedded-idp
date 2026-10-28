import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const read = name => readFile(new URL(`./${name}`, import.meta.url), "utf8");
const compilerOptions = { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext };
const browser = ts.transpileModule(await read("browser-session.ts"), { compilerOptions }).outputText;
const clientSource = (await read("account-security-client.ts")).replace(/^import \{ secureRandomUuid \} from "\.\/browser-session";$/m, browser);
const client = ts.transpileModule(clientSource, { compilerOptions }).outputText;
const source = await read("account-security-workflow.ts");
const workflowSource = source.replace(/^import \{[\s\S]*?\} from "\.\/account-security-client";$/m, client);
const mod = await import(`data:text/javascript;base64,${Buffer.from(ts.transpileModule(workflowSource, { compilerOptions }).outputText).toString("base64")}`);

const scope = "business:token:/tenant-a";
const owner = { tenant_id: "tenant-a", account_id: "account-a", session_id: "session-a", client_id: "client-a" };
class Store {
  raw = null;
  fail = false;
  dropWrite = false;
  failRead = false;
  read() { if (this.failRead) throw new Error("storage read blocked"); return this.raw; }
  compareAndSet(expected, next) {
    if (this.raw !== expected) throw new mod.AccountSecurityWorkflowError("journal_conflict");
    if (this.fail) throw new Error("storage blocked");
    if (!this.dropWrite) this.raw = next;
  }
}
class Port {
  accountSecurityScope = scope;
  session = owner;
  requests = [];
  handler = async () => ({ completed: true });
  getSnapshot() { return { session: this.session }; }
  async requestAccountSecurity(operation, body) {
    this.requests.push({ operation, body: structuredClone(body), raw: this.store.raw });
    return this.handler(operation, body);
  }
  forgetAccountSecuritySession() { this.session = undefined; }
  constructor(store) { this.store = store; }
}
function setup() {
  const store = new Store();
  const port = new Port(store);
  const workflow = new mod.AccountSecurityWorkflow(port, { enabled: true, recovery: true }, store);
  return { store, port, workflow };
}
const flow = { handle: "A".repeat(64), expires_at_unix_secs: 2_000_000_000 };

test("features default closed and validate exact boolean configuration", () => {
  assert.deepEqual(mod.validateAccountSecurityFeatures(), { enabled: false, recovery: false });
  assert.throws(() => mod.validateAccountSecurityFeatures({ enabled: false, recovery: true }), { code: "features_invalid" });
  assert.throws(() => mod.validateAccountSecurityFeatures({ enabled: true, recovery: false, extra: true }), { code: "features_invalid" });
});

test("password is persisted pending before request and never enters journal; success becomes completed", async () => {
  const { store, port, workflow } = setup();
  await workflow.changePassword("current-secret", "new-secret");
  assert.equal(port.requests.length, 1);
  assert.equal(JSON.parse(port.requests[0].raw).stage, "pending");
  assert.equal(port.requests[0].raw.includes("current-secret"), false);
  assert.equal(port.requests[0].raw.includes("new-secret"), false);
  assert.equal(JSON.parse(store.raw).stage, "completed");
  assert.equal(port.session, undefined);
});

test("storage failure blocks network writes", async () => {
  const { store, port, workflow } = setup();
  store.fail = true;
  await assert.rejects(workflow.changePassword("old", "new"));
  assert.equal(port.requests.length, 0);
});

test("a custom store that drops a CAS write is rejected by journal readback", async () => {
  const { store, port, workflow } = setup();
  store.dropWrite = true;
  await assert.rejects(workflow.changePassword("old", "new"), { code: "storage_unavailable" });
  assert.equal(port.requests.length, 0);
  assert.equal(workflow.getSnapshot().storageError, "storage_unavailable");
});

test("unknown recovery start stays pending and retry reuses the exact intent", async () => {
  const { store, port, workflow } = setup();
  port.handler = async () => { throw new Error("network"); };
  await assert.rejects(workflow.startRecovery("person@example.test"));
  const first = JSON.parse(store.raw);
  assert.equal(first.stage, "pending");
  assert.equal("flow" in first, false);
  port.handler = async () => flow;
  await workflow.retryStart();
  const second = JSON.parse(store.raw);
  assert.equal(second.stage, "ready");
  assert.deepEqual(second.intent, first.intent);
  assert.equal(port.requests[0].body.operation_id, port.requests[1].body.operation_id);
  assert.equal(port.requests[0].body.receipt_secret, port.requests[1].body.receipt_secret);
});

test("only exact status and code pairs are correctable", async () => {
  const { store, port, workflow } = setup();
  port.handler = async () => { throw { status: 503, code: "invalid_credentials" }; };
  await assert.rejects(workflow.changePassword("old", "new"), { code: "operation_unknown" });
  assert.equal(JSON.parse(store.raw).stage, "pending");
});

test("recovery completion persists pending with flow before sending and does not journal code or password", async () => {
  const { store, port, workflow } = setup();
  port.handler = async () => flow;
  await workflow.startRecovery("person@example.test");
  port.handler = async () => {
    assert.equal(JSON.parse(store.raw).stage, "pending");
    return { completed: true };
  };
  await workflow.completeRecovery("123456", "new-secret");
  const raw = store.raw;
  assert.equal(raw.includes("123456"), false);
  assert.equal(raw.includes("new-secret"), false);
  assert.equal(JSON.parse(raw).stage, "completed");
});

test("unknown completion can only check its result, not submit a second write", async () => {
  const { store, port, workflow } = setup();
  port.handler = async () => flow;
  await workflow.startRecovery("person@example.test");
  port.handler = async () => { throw new Error("network"); };
  await assert.rejects(workflow.completeRecovery("123456", "new-secret"));
  const writes = port.requests.filter(request => request.operation === "recovery-complete").length;
  await assert.rejects(workflow.completeRecovery("123456", "new-secret"), { code: "journal_exists" });
  assert.equal(port.requests.filter(request => request.operation === "recovery-complete").length, writes);
  port.handler = async () => ({ completed: false });
  await workflow.checkResult();
  assert.equal(JSON.parse(store.raw).stage, "pending");
});

test("false receipt result remains pending; true result completes", async () => {
  const { store, port, workflow } = setup();
  port.handler = async () => { throw new Error("network"); };
  await assert.rejects(workflow.revoke("tenant-b", "session-b"));
  port.handler = async () => ({ completed: false });
  await workflow.checkResult();
  assert.equal(JSON.parse(store.raw).stage, "pending");
  assert.equal(workflow.getSnapshot().error, "result_unconfirmed");
  port.handler = async () => ({ completed: true });
  await workflow.checkResult();
  assert.equal(JSON.parse(store.raw).stage, "completed");
});

test("stale instance refreshes journal and aborts before any network call", async () => {
  const store = new Store();
  const firstPort = new Port(store);
  const secondPort = new Port(store);
  const first = new mod.AccountSecurityWorkflow(firstPort, { enabled: true, recovery: true }, store);
  const second = new mod.AccountSecurityWorkflow(secondPort, { enabled: true, recovery: true }, store);
  firstPort.handler = async () => flow;
  await first.startRecovery("person@example.test");
  await assert.rejects(second.startRecovery("other@example.test"), { code: "journal_conflict" });
  assert.equal(secondPort.requests.length, 0);
  assert.equal(second.getSnapshot().record.intent.email, "person@example.test");
});

test("late successful response cannot overwrite a journal replaced during the request", async () => {
  const { store, port, workflow } = setup();
  let externalRaw;
  port.handler = async () => {
    const replacement = JSON.parse(store.raw);
    replacement.intent.email = "external@example.test";
    externalRaw = JSON.stringify(replacement);
    store.raw = externalRaw;
    return flow;
  };
  let reentrantWrite;
  let attemptedReentry = false;
  workflow.subscribe(() => {
    if (!attemptedReentry && workflow.getSnapshot().record?.intent.email === "external@example.test") {
      attemptedReentry = true;
      reentrantWrite = workflow.changePassword("old", "new").then(() => "unexpected-success", error => error.code);
    }
  });
  await assert.rejects(workflow.startRecovery("first@example.test"), { code: "journal_conflict" });
  assert.equal(await reentrantWrite, "operation_busy");
  assert.equal(workflow.getSnapshot().busy, false);
  assert.equal(store.raw, externalRaw);
  assert.equal(workflow.getSnapshot().record.intent.email, "external@example.test");
});

test("local SDK identity errors remain fixed and never make an unknown write ready", async () => {
  const { store, port, workflow } = setup();
  port.handler = async () => { port.session = undefined; return { completed: true }; };
  await assert.rejects(workflow.changePassword("old", "new"), { code: "security_session_changed" });
  assert.equal(JSON.parse(store.raw).stage, "pending");
  assert.equal(workflow.getSnapshot().error, "security_session_changed");
});

test("successful request whose completion readback fails is not rewritten to pending", async () => {
  const { store, port, workflow } = setup();
  port.handler = async () => { store.failRead = true; return flow; };
  await assert.rejects(workflow.startRecovery("person@example.test"), { code: "storage_unavailable" });
  assert.equal(JSON.parse(store.raw).stage, "ready");
  assert.equal(workflow.getSnapshot().storageError, "storage_unavailable");
});

test("corrupt journal blocks writes but explicit discard removes the original raw value", async () => {
  const store = new Store();
  store.raw = "{broken";
  const port = new Port(store);
  const workflow = new mod.AccountSecurityWorkflow(port, { enabled: true, recovery: true }, store);
  assert.equal(workflow.getSnapshot().storageError, "journal_corrupt");
  await assert.rejects(workflow.changePassword("old", "new"));
  assert.equal(port.requests.length, 0);
  workflow.discard();
  assert.equal(store.raw, null);
  assert.equal(workflow.getSnapshot().storageError, undefined);
});

test("read-only session listing remains available with disabled writes", async () => {
  const store = new Store();
  const port = new Port(store);
  port.handler = async () => ({ items: [], next_cursor: null });
  const workflow = new mod.AccountSecurityWorkflow(port, mod.validateAccountSecurityFeatures(), store);
  assert.deepEqual(await workflow.listSessions(), { items: [], next_cursor: null });
  await assert.rejects(workflow.startRecovery("person@example.test"), { code: "operation_disabled" });
});

test("read-only list remains available with corrupt storage and preserves write state", async () => {
  const store = new Store();
  store.raw = "not-json";
  const port = new Port(store);
  port.handler = async () => ({ items: [], next_cursor: null });
  const workflow = new mod.AccountSecurityWorkflow(port, { enabled: true, recovery: true }, store);
  assert.equal(workflow.getSnapshot().storageError, "journal_corrupt");
  assert.deepEqual(await workflow.listSessions(), { items: [], next_cursor: null });
  assert.equal(workflow.getSnapshot().storageError, "journal_corrupt");
});

test("list sessions does not clear an in-flight write busy state", async () => {
  const { port, workflow } = setup();
  let finish;
  let started;
  const began = new Promise(resolve => { started = resolve; });
  const response = new Promise(resolve => { finish = resolve; });
  port.handler = async operation => {
    if (operation === "password") { started(); return response; }
    return { items: [], next_cursor: null };
  };
  const write = workflow.changePassword("old", "new");
  await began;
  assert.equal(workflow.getSnapshot().busy, true);
  await workflow.listSessions();
  assert.equal(workflow.getSnapshot().busy, true);
  finish({ completed: true });
  await write;
  assert.equal(workflow.getSnapshot().busy, false);
});

test("discard read failure publishes a fixed storage error", () => {
  const { store, workflow } = setup();
  store.failRead = true;
  assert.throws(() => workflow.discard(), { code: "storage_unavailable" });
  assert.equal(workflow.getSnapshot().storageError, "storage_unavailable");
  assert.equal(workflow.getSnapshot().error, "storage_unavailable");
});

test("failed session reads and successful retries never alter the write snapshot", async () => {
  const { port, workflow } = setup();
  const original = workflow.getSnapshot();
  port.handler = async () => { throw { status: 503, code: "unavailable" }; };
  await assert.rejects(workflow.listSessions(), { code: "operation_unknown" });
  assert.equal(workflow.getSnapshot(), original);
  port.handler = async () => ({ items: [], next_cursor: null });
  assert.deepEqual(await workflow.listSessions(), { items: [], next_cursor: null });
  assert.equal(workflow.getSnapshot(), original);
});

test("a late session read failure cannot overwrite a completed write or new identity", async () => {
  const { port, store, workflow } = setup();
  let rejectRead;
  port.handler = async operation => operation === "sessions"
    ? new Promise((_, reject) => { rejectRead = reject; })
    : { completed: true };
  const read = workflow.listSessions();
  const failedRead = assert.rejects(read, { code: "operation_unknown" });
  await workflow.changePassword("old", "new");
  const completed = workflow.getSnapshot();
  const raw = store.raw;
  const newOwner = { ...owner, account_id: "other-account", session_id: "other-session" };
  port.session = newOwner;
  rejectRead(new Error("late list transport failure"));
  await failedRead;
  assert.equal(workflow.getSnapshot(), completed);
  assert.equal(workflow.getSnapshot().record.stage, "completed");
  assert.equal(store.raw, raw);
  assert.equal(port.session, newOwner);
});

for (const readyKind of ["recovery-start", "recovery-complete"]) {
  test(`invalid recovery input preserves ${readyKind} ready intent before any completion request`, async () => {
    const { port, store, workflow } = setup();
    port.handler = async () => flow;
    await workflow.startRecovery("person@example.test");
    if (readyKind === "recovery-complete") {
      port.handler = async () => { throw { status: 400, code: "invalid_recovery" }; };
      await assert.rejects(workflow.completeRecovery("123456", "new-password"), { code: "invalid_recovery" });
    }
    const ready = store.raw;
    const requestCount = port.requests.length;
    for (const [code, password] of [["1", "new-password"], ["abcdef", "new-password"], ["１２３４５６", "new-password"], [123456, "new-password"], ["123456", null]]) {
      await assert.rejects(workflow.completeRecovery(code, password), { code: "invalid_request" });
      assert.equal(store.raw, ready);
      assert.equal(workflow.getSnapshot().record.stage, "ready");
      assert.equal(workflow.getSnapshot().record.intent.kind, readyKind);
      assert.equal(port.requests.length, requestCount);
    }
    port.handler = async () => ({ completed: true });
    await workflow.completeRecovery("123456", "new-password");
    assert.equal(workflow.getSnapshot().record.stage, "completed");
    assert.equal(port.requests.length, requestCount + 1);
    if (readyKind === "recovery-complete") {
      assert.deepEqual(workflow.getSnapshot().record.intent, JSON.parse(ready).intent);
    }
  });
}
