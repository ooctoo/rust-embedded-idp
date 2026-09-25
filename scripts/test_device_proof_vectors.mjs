// Shared, synthetic Ed25519 fixtures: no production keys or credentials.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(new URL('../crates/embedded-idp-security/tests/fixtures/tenant_device_proof_v2.json', import.meta.url)));
const sha256 = bytes => createHash('sha256').update(bytes).digest('base64url');
// RFC 8410 PKCS#8 prefix, followed by a deliberately public test-only seed.
const privateKey = createPrivateKey({ key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'),
  Buffer.from(fixture.test_seed_hex, 'hex'),
]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
assert.equal(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url'), fixture.public_key);

for (const v of fixture.vectors) {
  let lines;
  if (v.kind === 'registration') {
    lines = ['EMBEDDED-IDP-DEVICE-REGISTRATION-V2', `tenant-id:${v.tenant_id}`,
      `device-id:${v.device_id}`, `key-id:${v.key_id}`, `challenge:${v.challenge}`];
  } else if (v.kind === 'rotation') {
    lines = ['EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2', `tenant-id:${v.tenant_id}`,
      `device-id:${v.device_id}`, `old-key-id:${v.old_key_id}`, `new-key-id:${v.key_id}`,
      `new-key-version:${v.key_version}`, `challenge:${v.challenge}`];
  } else {
    assert(['request', 'authentication'].includes(v.kind));
    lines = [v.profile, `tenant-id:${v.tenant_id}`, `audience:${v.audience}`, `method:${v.method}`,
      `path:${v.path}`, `body-sha256:${sha256(Buffer.from(v.body_utf8))}`, `challenge:${v.challenge}`,
      `device-id:${v.device_id}`, `key-id:${v.key_id}`, `signed-at:${v.signed_at}`];
  }
  if (v.kind === 'authentication') {
    const parts = v.credential_kind === 'password'
      ? ['tenant_login', v.client_id, v.login_entry, v.email, v.password]
      : v.credential_kind === 'refresh'
        ? ['refresh', v.client_id, v.login_entry, v.refresh_token]
        : v.credential_kind === 'authorization_code'
          ? ['authorization_code', v.client_id, v.login_entry, v.grant_type, v.code, v.redirect_uri, v.code_verifier, v.client_secret]
          : ['tenant_selection', v.client_id, v.login_entry, v.ticket];
    const hash = createHash('sha256').update('EMBEDDED-IDP-LOGIN-CREDENTIAL-V2\n');
    for (const part of parts) {
      const bytes = Buffer.from(part);
      const length = Buffer.alloc(8);
      length.writeBigUInt64BE(BigInt(bytes.length));
      hash.update(length).update(bytes);
    }
    const context = hash.digest('base64url');
    assert.equal(context, v.credential_sha256);
    lines.push(`credential-sha256:${context}`);
  }
  const text = `${lines.join('\n')}\n`;
  assert.equal(text, v.canonical_utf8, v.name);
  assert.equal(sha256(Buffer.from(text)), v.sha256, v.name);
  const signature = Buffer.from(v.signature, 'base64url');
  assert.equal(sign(null, Buffer.from(text), privateKey).toString('base64url'), v.signature, v.name);
  assert(verify(null, Buffer.from(text), publicKey, signature), v.name);
  for (const changed of [
    text.replace(`tenant-id:${v.tenant_id}\n`, 'tenant-id:other-tenant\n'),
    text.replace(`tenant-id:${v.tenant_id}\n`, ''),
    text.replace('-V2\n', '-V1\n').replace(`tenant-id:${v.tenant_id}\n`, ''),
    text.slice(0, -1),
    ...(v.kind === 'authentication' ? [text.replace(`credential-sha256:${v.credential_sha256}`, `credential-sha256:${sha256(Buffer.from('wrong-ticket'))}`)] : []),
  ]) assert.equal(verify(null, Buffer.from(changed), publicKey, signature), false, v.name);
}
console.log(`${fixture.vectors.length} tenant device-proof V2 vectors passed (Node Ed25519)`);
