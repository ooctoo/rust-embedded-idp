// Executes native-client.mjs in child processes with mocked HTTP and a temp state file.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = new URL('.', import.meta.url);
const client = new URL('./native-client.mjs', root);
const dir = await mkdtemp(join(tmpdir(), 'embedded-idp-native-scan-'));
const stateFile = join(dir, 'state.json');
const keyFile = join(dir, 'device.jwk');
const preload = join(dir, 'mock-fetch.mjs');
const logFile = join(dir, 'requests.jsonl');
try {
  const { privateKey } = generateKeyPairSync('ed25519');
  await writeFile(keyFile, JSON.stringify(privateKey.export({ format: 'jwk' })), { mode: 0o600 });
  await writeFile(stateFile, JSON.stringify({
    flow: 'claim', delivery_secret: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    claim_operation_id: '33333333-3333-4333-8333-333333333333', grant_id: 'old-grant',
    exchange_operation_id: 'old-exchange', ack_operation_id: 'old-ack',
    delivery: { receipt_nonce: 'old-receipt', tokens: { refresh_token: 'old-refresh' } },
  }), { mode: 0o600 });
  await writeFile(preload, `
import { appendFileSync } from 'node:fs';
globalThis.fetch = async (url, init) => {
  const path = new URL(url).pathname;
  const body = JSON.parse(init.body);
  appendFileSync(process.env.MOCK_LOG, JSON.stringify({ path, body }) + '\\n');
  const result = path.endsWith('/proof/challenges') ? { challenge: 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM' }
    : path.endsWith('/close-origin') ? { outcome: 'closed' }
    : { progress: { grant_id: 'new-grant' } };
  return { ok: true, async json() { return result; } };
};
`);
  const env = { ...process.env, IDP_ORIGIN: 'https://idp.example.test', SCAN_ENTRY_ID: 'terminal-login',
    SCAN_TENANT_ID: 'tenant-a', SCAN_DEVICE_ID: '88888888-8888-4888-8888-888888888888',
    SCAN_DEVICE_PRIVATE_JWK_FILE: keyFile, SCAN_STATE_FILE: stateFile, MOCK_LOG: logFile };
  const run = action => {
    const result = spawnSync(process.execPath, ['--import', preload, client.pathname, action], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  };

  run('close-origin');
  let state = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(state.flow, 'closed');
  assert.equal(state.origin_closed.action, 'claim');
  assert.equal(state.origin_closed.operation_id, '33333333-3333-4333-8333-333333333333');
  for (const key of ['delivery', 'grant_id', 'exchange_operation_id', 'ack_operation_id', 'delivery_secret']) {
    assert.equal(key in state, false, `${key} must be removed after closed`);
  }

  run('create');
  state = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(state.flow, 'create');
  assert.equal('origin_closed' in state, false);
  assert.notEqual(state.create_operation_id, '33333333-3333-4333-8333-333333333333');
  // Retrying the same flow executes the original operation and keeps its progress.
  run('create');
  const retried = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(retried.create_operation_id, state.create_operation_id);
  assert.equal(retried.delivery_secret, state.delivery_secret);
  assert.equal(retried.grant_id, 'new-grant');
  run('lookup');
  const requests = (await readFile(logFile, 'utf8')).trim().split('\n').map(JSON.parse);
  const lookup = requests.at(-1);
  assert.equal(lookup.path, '/auth/device-scan/lookup');
  assert.equal(lookup.body.origin_action, 'create');
  assert.equal(lookup.body.origin_operation_id, retried.create_operation_id);
  console.log('native scan client mocked execution passed');
} finally {
  await rm(dir, { recursive: true, force: true });
}
