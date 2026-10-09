// Design conformance only. The fixture seed is public synthetic test data.
// This does not exercise an implemented scan-login service or live database.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(new URL('../fixtures/device-scan-login-v1.json', import.meta.url)));
const digest = data => createHash('sha256').update(data).digest('base64url');
const privateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(fixture.test_seed_hex, 'hex'),
  ]),
  type: 'pkcs8', format: 'der',
});
const publicKey = createPublicKey(privateKey);
const publicJwk = publicKey.export({ format: 'jwk' });
assert.equal(publicJwk.x, fixture.public_jwk.x);
const thumbprint = digest(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: publicJwk.x }));
assert.equal(thumbprint, fixture.key_id);

function context(purpose, client, entry) {
  const hash = createHash('sha256').update('EMBEDDED-IDP-SCAN-CONTEXT-V1\n');
  for (const part of [purpose, client, entry]) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length).update(bytes);
  }
  return hash.digest('base64url');
}

const actions = new Map([
  ['create', 'scan_login_create'], ['claim', 'scan_login_claim'],
  ['status', 'scan_login_status'], ['lookup', 'scan_login_lookup'],
  ['cancel', 'scan_login_cancel'], ['exchange', 'scan_login_exchange'],
  ['recover', 'scan_login_recover'], ['acknowledge', 'scan_login_ack'],
  ['abort', 'scan_login_abort'], ['close-origin', 'scan_login_close_origin'],
]);
assert.equal(fixture.vectors.length, actions.size);
assert.equal(new Set(fixture.vectors.map(v => v.action)).size, actions.size);

let rejected = 0;
for (const v of fixture.vectors) {
  assert.equal(v.purpose, actions.get(v.action), v.name);
  assert.equal(v.profile, 'EMBEDDED-IDP-DEVICE-SCAN-V2');
  assert.equal(v.key_id, thumbprint);
  assert.equal(v.path, `/api/auth/device-scan/${v.action}`);
  assert.equal(JSON.parse(v.body_utf8).entry_id, v.entry_id);
  assert.equal(JSON.parse(v.body_utf8).tenant_id, v.tenant_id);
  const bodyDigest = digest(Buffer.from(v.body_utf8, 'utf8'));
  assert.equal(bodyDigest, v.body_sha256, v.name);
  const contextDigest = context(v.purpose, v.target_client_id, v.entry_id);
  assert.equal(contextDigest, v.context_sha256, v.name);
  const canonical = [
    v.profile, `tenant-id:${v.tenant_id}`, `audience:${v.audience}`,
    `method:${v.method}`, `path:${v.path}`, `body-sha256:${bodyDigest}`,
    `challenge:${v.challenge}`, `device-id:${v.device_id}`, `key-id:${v.key_id}`,
    `signed-at:${v.signed_at}`, `scan-context-sha256:${contextDigest}`, '',
  ].join('\n');
  assert.equal(canonical, v.canonical_utf8, v.name);
  assert.equal(digest(canonical), v.canonical_sha256, v.name);
  const signature = Buffer.from(v.signature, 'base64url');
  assert.equal(signature.length, 64);
  assert.equal(sign(null, Buffer.from(canonical), privateKey).toString('base64url'), v.signature);
  assert(verify(null, Buffer.from(canonical), publicKey, signature), v.name);

  const tampered = [
    canonical.replace(`tenant-id:${v.tenant_id}`, 'tenant-id:other'),
    canonical.replace(`audience:${v.audience}`, 'audience:other'),
    canonical.replace('method:POST', 'method:GET'),
    canonical.replace(v.path, v.path.replace('/api/', '/')),
    canonical.replace(`body-sha256:${bodyDigest}`, `body-sha256:${digest(v.body_utf8 + ' ')}`),
    canonical.replace(`challenge:${v.challenge}`, `challenge:${Buffer.alloc(32, 9).toString('base64url')}`),
    canonical.replace(`device-id:${v.device_id}`, 'device-id:99999999-9999-4999-8999-999999999999'),
    canonical.replace(`key-id:${v.key_id}`, `key-id:${Buffer.alloc(32, 5).toString('base64url')}`),
    canonical.replace(`signed-at:${v.signed_at}`, `signed-at:${v.signed_at + 1}`),
    canonical.replace(contextDigest, context('client_sync_transport', v.target_client_id, v.entry_id)),
    canonical.replace(contextDigest, context(v.purpose, 'other-client', v.entry_id)),
    canonical.replace(contextDigest, context(v.purpose, v.target_client_id, 'other-entry')),
    canonical.replace(v.profile, 'EMBEDDED-IDP-DEVICE-REQUEST-V2'),
    canonical.replaceAll('\n', '\r\n'),
    canonical.slice(0, -1),
  ];
  for (const changed of tampered) {
    assert.notEqual(changed, canonical);
    assert.equal(verify(null, Buffer.from(changed), publicKey, signature), false, v.name);
    rejected++;
  }
}
console.log(`${fixture.vectors.length} scan-login design vectors and ${rejected} signature tampering cases passed (Node Ed25519).`);
