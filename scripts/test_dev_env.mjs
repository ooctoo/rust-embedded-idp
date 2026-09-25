// Offline checks: external commands are replaced; no database or server required.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'idp-env-test-'));
const bin = join(temp, 'bin');
const log = join(temp, 'calls');
const common = join(temp, 'common.env');
const commonText = `EMBEDDED_IDP_APP_PG_URI='postgres://shared-test/unused'
EMBEDDED_IDP_TEST_PG_CONNECTION_URI='postgres://explicit-test/unused'
EMBEDDED_IDP_APP_EMAIL_FROM_NAME='Shared Test Sender'
EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE=log
EMBEDDED_IDP_APP_PG_SCHEMA=overridden_by_mode
`;
mkdirSync(bin);
for (const tool of ['pnpm', 'cargo', 'curl', 'openssl']) {
  writeFileSync(join(bin, tool), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2), env = process.env;
fs.appendFileSync(env.TEST_CALLS, JSON.stringify({tool:'${tool}',args,
  mode:env.EMBEDDED_IDP_APP_TENANCY_MODE, schema:env.EMBEDDED_IDP_APP_PG_SCHEMA,
  uri:env.EMBEDDED_IDP_APP_PG_URI, testUri:env.EMBEDDED_IDP_TEST_PG_CONNECTION_URI,
  issuer:env.EMBEDDED_IDP_APP_ISSUER,
  email:env.EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE, sender:env.EMBEDDED_IDP_APP_EMAIL_FROM_NAME,
  stdinLength: ('${tool}' === 'pnpm' || args.includes('bootstrap-admin')) ? fs.readFileSync(0).length : null
})+'\\n');
if ('${tool}' === 'pnpm' && env.FAIL_BUILD === '1') process.exit(7);
if ('${tool}' === 'curl' && args.includes('-o')) fs.writeFileSync(args[args.indexOf('-o') + 1], '<script src="./assets/index-test.js"></script>');
if ('${tool}' === 'curl' && args.includes('-w')) process.stdout.write(args.includes('-H') ? '200' : '401');
if ('${tool}' === 'openssl' && args.includes('-out')) fs.writeFileSync(args[args.indexOf('-out') + 1], Buffer.from('test-rsa-pkcs8-der'));
`, { mode: 0o700 });
}
const inherited = Object.fromEntries(Object.entries(process.env)
  .filter(([key]) => !key.startsWith('EMBEDDED_IDP_')));
function run(script, mode, args = [], extra = {}, input) {
  writeFileSync(log, '');
  const result = spawnSync(join(root, 'scripts', script), [mode, ...args], {
    cwd: temp, encoding: 'utf8', input, env: {
      ...inherited, PATH: `${bin}:${process.env.PATH}`, TEST_CALLS: log,
      EMBEDDED_IDP_COMMON_ENV_FILE: common,
      EMBEDDED_IDP_APP_ENV_FILE: join(temp, `${mode}.env`),
      EMBEDDED_IDP_APP_PG_URI: 'postgres://ambient/unused', ...extra,
    },
  });
  assert.ifError(result.error);
  return result;
}
const calls = () => readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
const entries = ['run_embedded_idp_app.sh', 'smoke_test_embedded_idp_app.sh', 'run_live_postgres_checks.sh'];
try {
  assert.equal(run('dev_env.sh', 'wrong', ['start']).status, 2);
  assert.equal(run('dev_env.sh', 'disabled', ['delete']).status, 2);
  assert.equal(run('dev_env.sh', 'disabled', ['access-db-init']).status, 2);
  for (const script of entries) {
    assert.notEqual(run(script, '').status, 0);
    assert.equal(calls().length, 0);
  }
  assert.notEqual(run('dev_env.sh', 'disabled', ['start']).status, 0);
  for (const mode of ['disabled', 'enabled']) {
    assert.equal(run('dev_env.sh', mode, ['init']).status, 0);
    const file = join(temp, `${mode}.env`);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(statSync(common).mode & 0o777, 0o600);
    const original = readFileSync(file, 'utf8');
    writeFileSync(common, commonText);
    assert.notEqual(run('dev_env.sh', mode, ['init']).status, 0);
    assert.equal(readFileSync(file, 'utf8'), original);
    assert.equal(readFileSync(common, 'utf8'), commonText);
    const testKey = join(temp, `${mode}.signing-key.der`);
    writeFileSync(common, `${readFileSync(common, 'utf8')}\nEMBEDDED_IDP_APP_SIGNING_KEY_FILE=${testKey}\n`);
    assert.equal(run('dev_env.sh', mode, ['key-init']).status, 0);
    assert.deepEqual(calls().map(c => c.tool), ['openssl', 'openssl']);
    assert.equal(statSync(testKey).mode & 0o777, 0o600);
    assert.notEqual(run('dev_env.sh', mode, ['key-init']).status, 0);
    assert.equal(calls().length, 0);
    // A mode override must win over the common setting, including quoted values.
    writeFileSync(file, original + '\nEMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE=smtp\n');
    const jobs = [
      ['dev_env.sh', ['db-init']], ['dev_env.sh', ['start']],
      ['dev_env.sh', ['bootstrap-admin', '--email', 'admin@example.test', '--password-stdin']],
      ...entries.map(script => [script, []]),
    ];
    for (const [script, args] of jobs) {
      const result = run(script, mode, args);
      assert.equal(result.status, 0, result.stderr);
      const observed = calls();
      assert.ok(observed.length > 0);
      for (const call of observed) {
        assert.equal(call.uri, 'postgres://shared-test/unused');
        assert.equal(call.testUri, 'postgres://explicit-test/unused');
        assert.equal(call.mode, mode);
        assert.equal(call.schema, `embedded_idp_${mode}_v2`);
        assert.equal(call.issuer, `http://127.0.0.1:${mode === 'disabled' ? 9100 : 9200}`);
        assert.equal(call.email, 'smtp');
        assert.equal(call.sender, 'Shared Test Sender');
      }
      if (args[0] === 'start' || script === 'run_embedded_idp_app.sh') {
        assert.deepEqual(observed.map(c => c.tool), ['pnpm', 'cargo']);
      }
      if (args[0] === 'db-init') assert.equal(observed[0].args.at(-1), '--access-schema');
      if (args[0] === 'bootstrap-admin') {
        assert.deepEqual(observed.map(c => c.tool), ['pnpm', 'cargo']);
        assert.deepEqual(observed[1].args.slice(-4), ['bootstrap-admin', '--email', 'admin@example.test', '--password-stdin']);
      }
      if (script === 'smoke_test_embedded_idp_app.sh') {
        assert.equal(observed.filter(call => call.tool === 'curl').length, 7);
      }
    }
  }
  assert.equal(run('dev_env.sh', 'enabled', ['bootstrap-admin', '--email', 'admin@example.test', '--password-stdin'], {}, 'FixtureAdmin123\n').status, 0);
  assert.deepEqual(calls().map(c => c.stdinLength), [0, 16]);
  assert.notEqual(run('dev_env.sh', 'disabled', ['start'], { FAIL_BUILD: '1' }).status, 0);
  assert.deepEqual(calls().map(c => c.tool), ['pnpm']);
  for (const script of entries) {
    assert.notEqual(run(script, 'disabled', [], { EMBEDDED_IDP_COMMON_ENV_FILE: join(temp, 'missing') }).status, 0);
    assert.equal(calls().length, 0);
    assert.notEqual(run(script, 'enabled', [], { EMBEDDED_IDP_APP_ENV_FILE: join(temp, 'disabled.env') }).status, 0);
    assert.equal(calls().length, 0);
  }
  writeFileSync(common, commonText.replace(/^EMBEDDED_IDP_TEST_PG_CONNECTION_URI=.*\n/m, ''));
  assert.notEqual(run('run_live_postgres_checks.sh', 'disabled').status, 0);
  assert.equal(calls().length, 0); // Never fall back to APP_PG_URI for live tests.
  const file = join(temp, 'disabled.env');
  writeFileSync(file, readFileSync(file, 'utf8').replace('embedded_idp_disabled_v2', 'public'));
  assert.notEqual(run('dev_env.sh', 'disabled', ['db-init']).status, 0);
  assert.equal(calls().length, 0);
  console.log('shared + mode configuration checks passed for all entry points');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
