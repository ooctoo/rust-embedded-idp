import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFunctionalCoverage, functionalManifest } from '/Volumes/Workspace/code/github/ooctoo/rust-embedded-idp/scripts/management_functional.mjs';
const out = await mkdtemp(join(tmpdir(), 'n2-pre-fix-repro-'));
try {
  const coverage = createFunctionalCoverage('n1', out, { env: { IDP_UI_PROFILE: 'ci-functional' } });
  for (const item of functionalManifest.suites.n1.cases.filter(c => c.selection === 'selected')) coverage.pass(item.case);
  let businessFailure;
  try { assert.deepEqual(['TypeError from pageerror'], []); }
  catch (error) { businessFailure = error; }
  finally {
    // Reproduce the old N1 placement: complete the reporter inside finally after the assertion failed.
    coverage.complete();
    await writeFile(join(out, 'results.json'), JSON.stringify({ pageErrors: ['TypeError from pageerror'] }));
  }
  const proof = JSON.parse(await readFile(join(out, 'functional-coverage.json'), 'utf8'));
  assert.equal(businessFailure?.name, 'AssertionError');
  assert.equal(proof.status, 'passed');
  console.log(JSON.stringify({ reproduction: 'old N1 finally order', businessFailure: businessFailure.name,
    pageErrors: JSON.parse(await readFile(join(out, 'results.json'), 'utf8')).pageErrors,
    incorrectCoverageStatus: proof.status, selectedCases: proof.selected.length }));
} finally { await rm(out, { recursive: true, force: true }); }
