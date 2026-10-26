// Offline failure-contract tests only; real browser coverage runs separately.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

for (const malformed of [false, true]) test(`invalid fixture fails closed and reports six unexecuted groups: malformed=${malformed}`, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ci-e2e-offline-'));
  try {
    const fixture = join(dir, 'state.json');
    if (malformed) await writeFile(fixture, '{"password":"DO_NOT_DISCLOSE",');
    const run = spawnSync(process.execPath, [fileURLToPath(new URL('./check_ci_e2e.mjs', import.meta.url))], {
      env: { ...process.env, IDP_UI_TEST_FIXTURE: fixture, IDP_UI_OUTPUT_DIR: dir }, encoding: 'utf8', timeout: 10000,
    });
    assert.equal(run.status, 1); assert.equal(run.error, undefined);
    const resultText = await readFile(join(dir, 'ci-e2e-results.json'), 'utf8');
    const result = JSON.parse(resultText);
    assert.equal(result.status, 'failed'); assert.equal(result.complete, false); assert.equal(result.failure_stage, 'fixture');
    assert.deepEqual(result.groups.map(g => g.id), ['E01', 'E02', 'E03', 'E04', 'E05', 'E06']);
    assert.ok(result.groups.every(g => g.status === 'not_run'));
    assert.equal(result.browser_closed, false);
    for (const output of [run.stdout, run.stderr, resultText]) {
      assert.ok(!output.includes('DO_NOT_DISCLOSE')); assert.ok(!output.includes(dir));
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
