import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const browserSource = await readFile(new URL("./browser-session.ts", import.meta.url), "utf8");
const source = await readFile(new URL("./account-security-client.ts", import.meta.url), "utf8");
const compilerOptions = { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext };
const browserModule = ts.transpileModule(browserSource, { compilerOptions }).outputText;
const securityModule = ts.transpileModule(
  source.replace(/^import \{ secureRandomUuid \} from "\.\/browser-session";$/m, browserModule),
  { compilerOptions },
).outputText;
const { AccountSecurityClient, AccountSecurityError, parseSecurityIntent } = await import(
  `data:text/javascript;base64,${Buffer.from(securityModule).toString("base64")}`
);

const scope = "business:token:/tenant-a";
const owner = (session = "session-a") => ({
  tenant_id: "tenant-a",
  account_id: "account-a",
  session_id: session,
  client_id: "client-a",
});
const handle = "A".repeat(64);

class FakePort {
  accountSecurityScope = scope;
  session = owner();
  requests = [];
  forgotten = [];
  handler = async () => ({ completed: true });

  getSnapshot() { return { ...(this.session ? { session: this.session } : {}) }; }

  requestAccountSecurity(operation, body, expected) {
    this.requests.push({ operation, body: structuredClone(body), expected });
    return this.handler(operation, body, expected);
  }

  forgetAccountSecuritySession(expected) {
    this.forgotten.push(expected);
    if (this.session && sameOwner(this.session, expected)) this.session = undefined;
  }
}

function sameOwner(left, right) {
  return ["tenant_id", "account_id", "session_id", "client_id"].every(key => left[key] === right[key]);
}

function startReceipt(intent, overrides = {}) {
  return { handle, expires_at_unix_secs: 2_000_000_000, ...overrides };
}

function recoveryBody(receipt) {
  return { operation_id: receipt.operation_id, receipt_secret: receipt.receipt_secret };
}

test("prepare freezes cryptographic intents without network calls and pages cross-tenant sessions", async () => {
  const port = new FakePort();
  port.handler = async operation => operation === "sessions" ? ({
    items: [
      { tenant_id: "tenant-a", session_id: "session-a", client_id: "client-a", purpose: "business", device_id: null,
        created_at: 10, expires_at: 20, status: "active", current: true },
      { tenant_id: "tenant-b", session_id: "session-b", client_id: "client-b", purpose: "management", device_id: "device-b",
        created_at: 5, expires_at: 15, status: "expired", current: false },
    ],
    next_cursor: "Y3Vyc29y",
  }) : { completed: true };
  const client = new AccountSecurityClient(port);
  const revoke = client.prepareRevocation("tenant-b", "session-b");
  const password = client.preparePasswordChange();
  const recovery = client.prepareRecoveryStart("  user@example.test  ");
  assert.equal(port.requests.length, 0);
  for (const intent of [revoke, password, recovery]) {
    assert.equal(Object.isFrozen(intent), true);
    assert.equal(intent.version, 1);
    assert.match(intent.operation_id, /^[0-9a-f-]{36}$/);
    assert.match(intent.receipt_secret, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(intent.receipt_secret, "A".repeat(43));
  }
  assert.equal(Object.isFrozen(revoke.owner), true);
  assert.equal(recovery.email, "user@example.test");
  assert.equal("password" in password, false);
  const page = await client.listSessions("Y3Vyc29y");
  assert.deepEqual(page.items.map(item => item.tenant_id), ["tenant-a", "tenant-b"]);
  assert.equal(page.items[1].device_id, "device-b");
  assert.equal(port.requests.at(-1).operation, "sessions");
  assert.deepEqual(port.requests.at(-1).body, { limit: 50, cursor: "Y3Vyc29y" });
  assert.deepEqual(port.requests.at(-1).expected, owner());
});

test("session pages reject mismarked current sessions and duplicate tenant/session identities", async () => {
  const row = { tenant_id: "tenant-b", session_id: "session-b", client_id: "client-b", purpose: "business",
    device_id: null, created_at: 10, expires_at: 20, status: "active", current: true };
  for (const items of [
    [row],
    [
      { ...row, current: false, tenant_id: "tenant-a", session_id: "session-a", client_id: "client-a" },
    ],
    [
      { ...row, current: false },
      { ...row, current: false },
    ],
  ]) {
    const port = new FakePort();
    port.handler = async () => ({ items, next_cursor: null });
    await assert.rejects(new AccountSecurityClient(port).listSessions(), { code: "invalid_security_response" });
  }
});

test("identity-bound actions reject a snapshot missing any required owner field", async () => {
  const port = new FakePort();
  port.session = { tenant_id: "tenant-a", account_id: "account-a", session_id: "session-a" };
  const client = new AccountSecurityClient(port);
  assert.throws(() => client.preparePasswordChange(), { code: "security_session_changed" });
  assert.equal(port.requests.length, 0);
});

test("recovery reuses unchanged frozen receipts and keeps passwords out of intents", async () => {
  const port = new FakePort();
  const client = new AccountSecurityClient(port);
  const intent = client.prepareRecoveryStart(" user@example.test ");
  port.handler = async operation => operation === "recovery-start" ? startReceipt(intent) : { completed: true };
  const first = await client.startRecovery(intent);
  const second = await client.startRecovery(intent);
  assert.deepEqual(first, second);
  assert.equal(port.requests.length, 2);
  assert.deepEqual(port.requests[0].body, {
    email: "user@example.test",
    operation_id: intent.operation_id,
    receipt_secret: intent.receipt_secret,
  });
  assert.deepEqual(port.requests[1].body, port.requests[0].body);

  const completion = client.prepareRecoveryCompletion(handle);
  assert.equal("code" in completion, false);
  assert.equal("password" in completion, false);
  await client.completeRecovery(completion, "123456", "New-Password-123!");
  assert.equal(port.requests.at(-1).operation, "recovery-complete");
  assert.deepEqual(port.requests.at(-1).body, {
    handle,
    code: "123456",
    new_password: "New-Password-123!",
    operation_id: completion.operation_id,
    receipt_secret: completion.receipt_secret,
  });
  assert.equal(JSON.stringify(completion).includes("New-Password-123!"), false);
  assert.equal(port.forgotten.length, 0, "anonymous recovery never guesses which identity to clear");
});

test("anonymous recovery result works without a session and false does not clear identity", async () => {
  const port = new FakePort();
  const client = new AccountSecurityClient(port);
  const intent = client.prepareRecoveryCompletion(handle);
  port.session = undefined;
  port.handler = async () => ({ completed: false });
  assert.deepEqual(await client.result(intent), { completed: false });
  assert.equal(port.requests[0].operation, "recovery-result");
  assert.equal(port.requests[0].expected, undefined);
  assert.deepEqual(port.requests[0].body, recoveryBody(intent));
  assert.equal(port.forgotten.length, 0);
});

test("password and current-session revocation clear only the precise owner after confirmed success", async () => {
  const port = new FakePort();
  const client = new AccountSecurityClient(port);
  const password = client.preparePasswordChange();
  await client.changePassword(password, "Current-Password-1!", "New-Password-2!");
  assert.deepEqual(port.forgotten, [owner()]);
  assert.equal(port.session, undefined);

  port.session = owner();
  const currentRevoke = client.prepareRevocation("tenant-a", "session-a");
  await client.revoke(currentRevoke);
  assert.deepEqual(port.forgotten.at(-1), owner());
  assert.equal(port.session, undefined);

  port.session = owner();
  const otherRevoke = client.prepareRevocation("tenant-b", "session-b");
  const before = port.forgotten.length;
  await client.revoke(otherRevoke);
  assert.equal(port.forgotten.length, before);
});

test("confirmed password result clears only the matching owner and late responses cannot clear a new owner", async () => {
  const port = new FakePort();
  const client = new AccountSecurityClient(port);
  const intent = client.preparePasswordChange();
  port.session = undefined;
  assert.deepEqual(await client.result(intent), { completed: true });
  assert.equal(port.requests[0].expected, undefined);
  assert.deepEqual(port.forgotten, [owner()]);

  port.session = owner();
  assert.deepEqual(await client.result(intent), { completed: true });
  assert.equal(port.session, undefined, "result=true forgets only the still-matching owner");

  port.session = owner();
  const pendingIntent = client.preparePasswordChange();
  let resolveRequest;
  port.handler = () => new Promise(resolve => { resolveRequest = resolve; });
  const pending = client.changePassword(pendingIntent, "Current-Password-1!", "New-Password-2!");
  port.session = owner("session-new");
  resolveRequest({ completed: true });
  await assert.rejects(pending, error => error.code === "security_session_changed");
  assert.deepEqual(port.forgotten, [owner(), owner()]);
});

test("parseSecurityIntent freezes exact DTOs and rejects scope, shape, secret, and secret-field drift", () => {
  const port = new FakePort();
  const client = new AccountSecurityClient(port);
  const intent = client.prepareRecoveryStart("person@example.test");
  assert.equal(Object.isFrozen(parseSecurityIntent(intent, scope)), true);
  for (const invalid of [
    { ...intent, scope: "other-scope" },
    { ...intent, version: 2 },
    { ...intent, kind: "password" },
    { ...intent, receipt_secret: "A".repeat(43) },
    { ...intent, password: "must-not-be-stored" },
    { ...intent, code: "123456" },
    { ...intent, token: "must-not-be-stored" },
  ]) {
    assert.throws(() => parseSecurityIntent(invalid, scope), error => error.code === "invalid_security_intent");
  }
  assert.throws(() => parseSecurityIntent(intent, "wrong-scope"), { code: "invalid_security_intent" });
  assert.throws(() => client.prepareRecoveryCompletion("not-a-handle"), { code: "invalid_security_intent" });
});

test("invalid successful DTOs and non-canonical completion codes are rejected", async () => {
  const port = new FakePort();
  const client = new AccountSecurityClient(port);
  const recovery = client.prepareRecoveryStart("person@example.test");
  port.handler = async () => startReceipt(recovery, { expires_at_unix_secs: -1 });
  await assert.rejects(client.startRecovery(recovery), { code: "invalid_security_response" });
  const completion = client.prepareRecoveryCompletion(handle);
  await assert.rejects(client.completeRecovery(completion, "１２３４５６", "New-Password-123!"), { code: "invalid_security_intent" });
  assert.equal(port.requests.length, 1);

  const malformedMutation = new FakePort();
  malformedMutation.handler = async () => ({ completed: true, extra: "unexpected" });
  const mutationClient = new AccountSecurityClient(malformedMutation);
  const password = mutationClient.preparePasswordChange();
  await assert.rejects(
    mutationClient.changePassword(password, "Current-Password-1!", "New-Password-2!"),
    { code: "invalid_security_response" },
  );
  assert.equal(malformedMutation.forgotten.length, 0, "malformed success does not clear owner");
  assert.deepEqual(malformedMutation.session, owner());
});
