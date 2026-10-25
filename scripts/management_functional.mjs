// Explicit tool-only CI selection. Default desktop acceptance keeps its legacy path.
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync, writeFileSync, renameSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export const isFunctionalProfile = (env = process.env) => env.IDP_UI_PROFILE === 'ci-functional';
export const functionalOnly = isFunctionalProfile();
export const functionalManifest = JSON.parse(readFileSync(new URL('./n2-ci/functional-cases.json', import.meta.url), 'utf8'));

function passArgument(line) {
  const marker = line.indexOf('pass(');
  if (marker < 0) return null;
  let depth = 1, quote = null;
  for (let index = marker + 5; index < line.length; index++) {
    const char = line[index];
    if (quote) {
      if (char === '\\') index++;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"' || char === '`') quote = char;
    else if (char === '(') depth++;
    else if (char === ')' && --depth === 0) return line.slice(marker + 5, index);
  }
  return null;
}

export function functionalCaseSourceMatches(name, line) {
  const argument = passArgument(line);
  if (argument === null) return false;
  const singleQuoted = `'${name.replaceAll('\\', '\\\\').replaceAll("'", "\\'")}'`;
  if (argument.includes(JSON.stringify(name)) || argument.includes(singleQuoted)) return true;
  for (const [, template] of argument.matchAll(/`((?:\\.|[^`])*)`/g)) {
    const chunks = template.split(/\$\{[^{}]*\}/);
    const pattern = chunks.map(chunk => chunk.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
    if (new RegExp(`^${pattern}$`).test(name)) return true;
  }
  return false;
}

export function createFunctionalCoverage(suite, output, { env = process.env, manifest = functionalManifest } = {}) {
  if (!isFunctionalProfile(env)) return { pass() {}, complete() {}, fail() {} };
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.profile, 'ci-functional');
  const definition = manifest.suites[suite];
  assert.ok(definition?.cases.length, 'Unknown or empty functional suite');
  const byName = new Map(), ids = new Set();
  for (const item of definition.cases) {
    assert.ok(item.case && item.id && item.source?.path && Number.isInteger(item.source.line));
    assert.ok(['selected', 'excluded'].includes(item.selection));
    assert.ok(!byName.has(item.case) && !ids.has(item.id), 'Duplicate functional manifest case or ID');
    assert.ok(item.selection !== 'excluded' || item.reason, 'Excluded case requires a reason');
    byName.set(item.case, item); ids.add(item.id);
  }
  const selected = definition.cases.filter(c => c.selection === 'selected');
  assert.ok(selected.length, 'Functional suite must select cases');
  const executed = new Set();
  const result = {
    schemaVersion: 1, profile: 'ci-functional', suite, status: 'running',
    selected: selected.map(c => ({ id: c.id, case: c.case, source: c.source })),
    executed: [], excluded: definition.cases.filter(c => c.selection === 'excluded'),
    missing: selected.map(c => c.id),
  };
  mkdirSync(output, { recursive: true });
  const destination = join(output, 'functional-coverage.json');
  function persist() {
    const temporary = destination + '.tmp';
    writeFileSync(temporary, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
    renameSync(temporary, destination);
  }
  function reject(reason) {
    result.status = 'failed'; result.rejection = reason; persist();
    throw new Error(`Functional coverage rejected: ${reason}`);
  }
  persist();
  return {
    pass(name) {
      if (result.status !== 'running') reject('case-after-finalization');
      const item = byName.get(name);
      if (!item) reject('unknown-case');
      if (item.selection !== 'selected') reject('excluded-case-executed');
      if (executed.has(item.id)) reject('duplicate-case');
      executed.add(item.id);
      result.executed.push({ id: item.id, case: item.case, source: item.source });
      result.missing = selected.filter(c => !executed.has(c.id)).map(c => c.id);
      persist();
    },
    complete() {
      if (result.status !== 'running') reject('completion-after-finalization');
      if (result.missing.length) reject('missing-selected-cases');
      result.status = 'passed'; persist();
    },
    fail(reason) {
      result.status = 'failed'; result.rejection = String(reason || 'RunFailed').slice(0, 80); persist();
    },
  };
}

export async function finalizeFunctionalRun({ coverage, contexts, browser, resultPath, result, failure }) {
  const cleanupErrors = [];
  for (const [index, context] of contexts.entries()) {
    try { await context.close(); }
    catch (error) { cleanupErrors.push({ resource: 'browser-context', index, error: error?.name ?? 'Error' }); }
  }
  try { await browser.close(); }
  catch (error) { cleanupErrors.push({ resource: 'browser', error: error?.name ?? 'Error' }); }

  let finalFailure = failure ?? null;
  if (!finalFailure && cleanupErrors.length) finalFailure = new Error('Browser cleanup failed');
  if (!finalFailure && result.pageErrors?.length) finalFailure = new Error('Browser page errors');
  try {
    if (finalFailure) coverage.fail(finalFailure?.name ?? 'Error');
    else coverage.complete();
  } catch (error) {
    finalFailure ??= error;
    try { coverage.fail(finalFailure?.name ?? 'Error'); } catch {}
  }

  const payload = {
    ...result,
    complete: !finalFailure && cleanupErrors.length === 0,
    cleanupErrors,
    failure: finalFailure ? { name: finalFailure?.name ?? 'Error' } : null,
  };
  try { await writeFile(resultPath, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 }); }
  catch (error) {
    if (!finalFailure) {
      finalFailure = error;
      try { coverage.fail(error?.name ?? 'Error'); } catch {}
      throw error;
    }
  }
  if (finalFailure && !failure) throw finalFailure;
}
