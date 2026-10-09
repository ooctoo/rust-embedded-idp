#!/usr/bin/env node
/*
 * Generic native-device protocol example. It intentionally does not render a
 * QR code in this repository. It persists the protected delivery bundle in a
 * caller-selected owner-only state file; a real native host should instead use
 * platform secure storage.
 */
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { originForVerification, prepareFlow, recordClosedOrigin } from './native-client-state.mjs';

const origin = required('IDP_ORIGIN').replace(/\/$/, '');
const entryId = required('SCAN_ENTRY_ID');
const tenantId = required('SCAN_TENANT_ID');
const deviceId = required('SCAN_DEVICE_ID');
const privateJwk = JSON.parse(await readFile(required('SCAN_DEVICE_PRIVATE_JWK_FILE'), 'utf8'));
const targetClientId = process.env.SCAN_TARGET_CLIENT_ID ?? 'desktop-app';
const audience = process.env.SCAN_PROOF_AUDIENCE ?? 'embedded-idp-business';
const stateFile = process.env.SCAN_STATE_FILE ?? '.local/device-scan-login-state.json';
const action = process.argv[2] ?? 'help';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
function uuid() { return crypto.randomUUID(); }
function b64url(bytes) { return Buffer.from(bytes).toString('base64url'); }
function sha256(value) { return b64url(createHash('sha256').update(value).digest()); }
async function loadState() {
  try { return JSON.parse(await readFile(stateFile, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return {}; throw error; }
}
async function saveState(next) {
  await mkdir(dirname(stateFile), { recursive: true, mode: 0o700 });
  const temporary = `${stateFile}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    const file = await open(temporary, 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(next)); await file.sync(); }
    finally { await file.close(); }
    await chmod(temporary, 0o600);
    await rename(temporary, stateFile);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
  const directory = await open(dirname(stateFile), 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}
async function request(path, body, headers = {}) {
  const raw = JSON.stringify(body);
  const response = await fetch(`${origin}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: raw });
  const data = await response.json();
  if (!response.ok) throw new Error(`${data.error ?? response.status}: ${data.message ?? 'request failed'}`);
  return data;
}
function contextDigest(purpose) {
  const hash = createHash('sha256').update('EMBEDDED-IDP-SCAN-CONTEXT-V1\n');
  for (const part of [purpose, targetClientId, entryId]) {
    const bytes = Buffer.from(part, 'utf8');
    const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(size).update(bytes);
  }
  return hash.digest('base64url');
}
async function deviceRequest(path, body, purpose, needsEntry = false) {
  const challenge = await request('/devices/proof/challenges', { tenant_id: tenantId, device_id: deviceId, purpose });
  const raw = JSON.stringify(needsEntry ? { ...body, entry_id: entryId, tenant_id: tenantId } : { ...body, tenant_id: tenantId });
  const signedAt = Math.floor(Date.now() / 1000);
  const key = createPrivateKey({ key: privateJwk, format: 'jwk' });
  const publicJwk = createPublicKey(key).export({ format: 'jwk' });
  const keyId = sha256(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: publicJwk.x }));
  const canonical = [
    'EMBEDDED-IDP-DEVICE-SCAN-V2', `tenant-id:${tenantId}`, `audience:${audience}`,
    'method:POST', `path:${path}`, `body-sha256:${sha256(Buffer.from(raw))}`,
    `challenge:${challenge.challenge}`, `device-id:${deviceId}`, `key-id:${keyId}`,
    `signed-at:${signedAt}`, `scan-context-sha256:${contextDigest(purpose)}`, '',
  ].join('\n');
  const signature = b64url(sign(null, Buffer.from(canonical), key));
  const response = await fetch(`${origin}${path}`, { method: 'POST', headers: {
    'content-type': 'application/json', 'x-device-id': deviceId, 'x-device-key-id': keyId,
    'x-device-challenge': challenge.challenge, 'x-device-signature': signature,
    'x-device-signed-at': String(signedAt),
  }, body: raw });
  const result = await response.json();
  if (!response.ok) throw new Error(`${result.error ?? result.code ?? response.status}: ${result.message ?? 'request failed'}`);
  return result;
}
function safeOutput(result) {
  const copy = structuredClone(result);
  if (copy.tokens) copy.tokens = '[REDACTED: persist before ack]';
  if (copy.receipt_nonce) copy.receipt_nonce = '[REDACTED]';
  console.log(JSON.stringify(copy, null, 2));
}
async function persistDelivery(result) {
  const issuanceOperationId = result.progress?.issuance_operation_id;
  if (!result.tokens || !result.receipt_nonce || !issuanceOperationId) return;
  const existing = state.delivery;
  if (existing?.acknowledged) return; // Ignore late bundle responses after activation.
  if (existing && (existing.issuance_operation_id !== issuanceOperationId
    || existing.session_id !== result.session?.session_id)) {
    throw new Error('late delivery result belongs to a different session; retained the existing protected bundle and require operator review');
  }
  await remember({ grant_id: result.progress?.grant_id ?? state.grant_id,
    exchange_operation_id: issuanceOperationId,
    delivery: { issuance_operation_id: issuanceOperationId, session_id: result.session?.session_id,
      receipt_nonce: result.receipt_nonce, tokens: result.tokens } });
}

let state = await loadState();
async function remember(patch) { state = { ...state, ...patch }; await saveState(state); }
async function replaceState(next) { state = next; await saveState(state); }
if (action === 'create') {
  const deliverySecret = state.flow === 'create' ? state.delivery_secret : b64url(randomBytes(32));
  const operationId = state.flow === 'create' ? state.create_operation_id : uuid();
  await replaceState(prepareFlow(state, 'create', deliverySecret, operationId));
  const result = await deviceRequest('/auth/device-scan/create', { operation_id: operationId, delivery_secret_hash: sha256(Buffer.from(deliverySecret, 'base64url')) }, 'scan_login_create', true);
  await remember({ grant_id: result.progress?.grant_id });
  if (result.display_code && result.verification_uri) {
    console.log(`verification_url: ${result.verification_uri}#code=${encodeURIComponent(result.display_code)}`);
  }
  safeOutput(result); // Render display_code using the host's QR component.
} else if (action === 'claim') {
  const scanCode = required('SCAN_CODE');
  const deliverySecret = state.flow === 'claim' ? state.delivery_secret : b64url(randomBytes(32));
  const operationId = state.flow === 'claim' ? state.claim_operation_id : uuid();
  await replaceState(prepareFlow(state, 'claim', deliverySecret, operationId));
  const result = await deviceRequest('/auth/device-scan/claim', { operation_id: operationId, scan_code: scanCode, delivery_secret_hash: sha256(Buffer.from(deliverySecret, 'base64url')) }, 'scan_login_claim', true);
  await remember({ grant_id: result.grant_id ?? result.progress?.grant_id });
  safeOutput(result);
} else if (action === 'lookup') {
  const origin = originForVerification(state);
  const result = await deviceRequest('/auth/device-scan/lookup', { origin_action: origin.action, origin_operation_id: origin.operation_id, delivery_secret: origin.delivery_secret }, 'scan_login_lookup', true);
  await remember({ grant_id: result.progress?.grant_id ?? state.grant_id });
  safeOutput(result);
} else if (action === 'close-origin') {
  const origin = originForVerification(state);
  const result = await deviceRequest('/auth/device-scan/close-origin', { origin_action: origin.action, origin_operation_id: origin.operation_id, delivery_secret: origin.delivery_secret }, 'scan_login_close_origin', true);
  // This mutation happens only after a response. Lost responses retain retry state.
  if (result.outcome === 'closed') await replaceState(recordClosedOrigin(state, origin, sha256(Buffer.from(origin.delivery_secret, 'base64url'))));
  safeOutput(result);
} else if (action === 'status' || action === 'exchange' || action === 'recover' || action === 'abort' || action === 'cancel') {
  if (!state.grant_id || !state.delivery_secret) throw new Error('no protected active flow state');
  const access = { grant_id: state.grant_id, delivery_secret: state.delivery_secret };
  if (action === 'exchange' && !state.exchange_operation_id) await remember({ exchange_operation_id: uuid() });
  if (action === 'cancel' && !state.cancel_operation_id) await remember({ cancel_operation_id: uuid() });
  if (action === 'abort' && !state.abort_operation_id) await remember({ abort_operation_id: uuid() });
  const result = action === 'status'
    ? await deviceRequest('/auth/device-scan/status', access, 'scan_login_status')
    : action === 'exchange'
      ? await deviceRequest('/auth/device-scan/exchange', { operation_id: state.exchange_operation_id, ...access }, 'scan_login_exchange')
      : action === 'recover'
        ? await deviceRequest('/auth/device-scan/recover', { issuance_operation_id: process.env.SCAN_ISSUANCE_OPERATION_ID ?? state.delivery?.issuance_operation_id ?? state.exchange_operation_id ?? required('SCAN_ISSUANCE_OPERATION_ID'), ...access }, 'scan_login_recover')
        : action === 'abort'
          ? await deviceRequest('/auth/device-scan/abort', { operation_id: state.abort_operation_id, issuance_operation_id: process.env.SCAN_ISSUANCE_OPERATION_ID ?? state.delivery?.issuance_operation_id ?? state.exchange_operation_id ?? required('SCAN_ISSUANCE_OPERATION_ID'), ...access }, 'scan_login_abort')
          : await deviceRequest('/auth/device-scan/cancel', { operation_id: state.cancel_operation_id, ...access }, 'scan_login_cancel');
  if (action === 'exchange' || action === 'recover') await persistDelivery(result);
  safeOutput(result);
} else if (action === 'ack') {
  if (state.delivery?.acknowledged) { safeOutput(await deviceRequest('/auth/device-scan/status', { grant_id: state.grant_id, delivery_secret: state.delivery_secret }, 'scan_login_status')); process.exit(0); }
  if (!state.delivery || !state.grant_id || !state.delivery_secret) throw new Error('no persisted delivery bundle to acknowledge');
  const operationId = state.ack_operation_id ?? uuid();
  await remember({ ack_operation_id: operationId });
  const result = await deviceRequest('/auth/device-scan/acknowledge', {
    operation_id: operationId, issuance_operation_id: state.delivery.issuance_operation_id,
    grant_id: state.grant_id, delivery_secret: state.delivery_secret, receipt_nonce: state.delivery.receipt_nonce,
  }, 'scan_login_ack');
  // Keep the active session credentials; receipt material is no longer needed.
  if (result.delivery_state === 'acknowledged' || result.progress?.delivery_state === 'acknowledged') {
    const { receipt_nonce, ...delivery } = state.delivery;
    await remember({ delivery: { ...delivery, acknowledged: true }, ack_operation_id: operationId });
  }
  safeOutput(result);
} else if (action === 'logout') {
  throw new Error('After acknowledgement, use the host’s normal exact-session logout adapter with the protected refresh token. Do not use scan cancel/abort to log out an active session.');
} else {
  console.log('actions: create | claim (SCAN_CODE=...) | lookup | close-origin | status | exchange | recover [SCAN_ISSUANCE_OPERATION_ID=...] | ack | cancel | abort [SCAN_ISSUANCE_OPERATION_ID=...] | logout');
}
