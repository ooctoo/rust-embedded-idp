"""N2 CI orchestration. Only explicit hosted Linux arm64 execution can create fixtures.

The offline unit tests import helpers and replace all Docker/browser operations.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from n2_ci_runtime import process_identity, run_bounded
from prepare_management_n2_linux import Fixture, ci_identity, verify_docker_context

ROOT = Path(__file__).resolve().parent.parent
SUITES = ['gates', 'n2_mac', 'navigation', 'clients', 'authorization', 'security', 'n1', 'console']
BASES = {k: v['reference'] for k, v in json.loads((ROOT / 'docs/design/n2/linux-docker-20261025/images/frozen.json').read_text()).items()}
MANIFEST = ROOT / 'scripts/n2-ci/functional-cases.json'
RUNTIME_MANIFEST = ROOT / 'scripts/n2-ci/runtime-cases.json'
RESULT_FILES = dict(navigation='ui-b-results.json', clients='ui-c-results.json',
                    authorization='ui-d-results.json', security='ui-e-results.json',
                    n1='n1-browser-results.json', console='results.json')
PUBLIC_NAMES = {
    'environment.json', 'source-manifest.json', 'image-summary.json', 'failure.json',
    'tool-manifest.json', 'results.json', 'functional-coverage.json', 'execution.json',
    'ui-b-results.json', 'ui-c-results.json', 'ui-d-results.json', 'ui-e-results.json',
    'n1-browser-results.json', 'l05-restart-results.json', 'served-assets.json',
    'runtime-manifest.json', 'suite-summary.json', 'final-summary.json', 'publication.json',
}
SECRET_PATTERNS = [r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
                   r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                   r'\b(?:postgres(?:ql)?|https?)://[^\s/\"<>]+:[^\s/\"<>]+@',
                   r'(?i)(?:authorization|set-cookie)\s*[:=]\s*(?:Bearer\s+|[^\s]+=[^\s;]+)',
                   r'(?i)"(?:password|client_secret|access_token|refresh_token|db_password|db_uri|private_key|cookie|authorization)"\s*:\s*"(?!\[redacted\])[^\"]+"']


def write_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.next')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def read_json(path):
    return json.loads(Path(path).read_text())


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


@contextlib.contextmanager
def deadline(seconds):
    previous = os.environ.get('IDP_N2_DEADLINE')
    os.environ['IDP_N2_DEADLINE'] = str(time.monotonic() + max(0, seconds))
    try:
        yield
    finally:
        if previous is None: os.environ.pop('IDP_N2_DEADLINE', None)
        else: os.environ['IDP_N2_DEADLINE'] = previous


def remaining_job(work, reserve=1080):
    started = float((work / 'job-started-at').read_text())
    if not 0 <= time.time() - started < 24 * 3600:
        raise ValueError('Invalid job start time')
    return max(0, 7200 - (time.time() - started) - reserve)


def command(args, *, timeout=30, env=None):
    return run_bounded(args, cwd=ROOT, env=env, timeout=timeout, check=True).stdout.strip()


def tool_manifest():
    paths = [p for p in ROOT.joinpath('scripts').rglob('*')
             if p.is_file() and not p.is_symlink() and
             'node_modules' not in p.parts and '__pycache__' not in p.parts and
             (p.suffix in {'.py', '.mjs', '.json', '.yaml', '.md'} or p.name.startswith('Dockerfile'))]
    paths += [ROOT / '.github/workflows/n2-functional.yml', ROOT / 'Cargo.lock', ROOT / 'web/pnpm-lock.yaml',
              ROOT / 'docs/design/n2/linux-docker-20261025/images/frozen.json']
    return {str(p.relative_to(ROOT)): sha256(p) for p in sorted(set(paths))}


def safe_text(value, secrets=(), private=None):
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        value = value.replace(secret, '[redacted]')
    for original, replacement in [(str(ROOT), '<repo>'), (str(Path.home()), '<home>'),
                                  (str(private) if private else '', '<private>')]:
        if original: value = value.replace(original, replacement)
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, value):
            raise ValueError('Secret pattern detected')
    return value


def public_name(path):
    return (path.name in PUBLIC_NAMES or bool(re.fullmatch(r'(?:enabled|disabled|fixed|choose)-runtime\.txt', path.name)) or
            bool(re.fullmatch(r'(?:input-(?:node|rust|runtime)-image|build-(?:runtime|prepare)|pull-(?:node|rust|runtime|postgres))\.log', path.name)))


def checker_diagnostic(stderr):
    # Playwright call logs may contain typed passwords. Publish only source locations.
    return {'sourceFrames': sorted(set(re.findall(r'scripts/[A-Za-z0-9_./-]+\.(?:mjs|py):[0-9]+(?::[0-9]+)?', stderr)))}


def publish(source, destination, secrets=(), private=None):
    """Only decoded, scanned, explicitly named files can enter the upload root."""
    errors = []
    if not source.exists(): return errors
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            errors.append({'file': str(path.relative_to(source)), 'error': 'SymlinkRejected'}); continue
        if not path.is_file(): continue
        relative = path.relative_to(source)
        if not public_name(path):
            errors.append({'file': str(relative), 'error': 'NotWhitelisted'}); continue
        try:
            value = safe_text(path.read_text(encoding='utf-8'), secrets, private)
            if path.suffix == '.json': json.loads(value)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as stream:
                stream.write(value)
        except (ValueError, OSError, UnicodeError) as error:
            errors.append({'file': str(relative), 'error': type(error).__name__})
    return errors


def validate_coverage(suite, output, *, persist_runtime=True):
    if suite in ['gates', 'n2_mac']:
        definition = read_json(RUNTIME_MANIFEST)['suites'][suite]
        found = []
        for filename in definition['resultFiles']:
            result = read_json(output / filename)
            if result.get('complete') is not True or result.get('cleanupErrors'):
                raise ValueError('Incomplete runtime/session result')
            names = [item if isinstance(item, str) else item['name'] for item in result['cases']]
            expected = [c['case'] for c in definition['cases'] if c['resultFile'] == filename]
            if len(names) != len(set(names)) or set(names) != set(expected):
                raise ValueError('Runtime/session case selection mismatch')
            found += [dict(item, status='passed') for item in definition['cases'] if item['resultFile'] == filename]
        expected_coverage = {
            'suite': suite, 'profile': 'ci-functional', 'status': 'passed',
            'selected': definition['cases'], 'executed': found, 'excluded': [], 'missing': []}
        if persist_runtime:
            write_json(output / 'functional-coverage.json', expected_coverage)
        elif read_json(output / 'functional-coverage.json') != expected_coverage:
            raise ValueError('Runtime/session coverage mismatch')
        return
    definition = read_json(MANIFEST)['suites'][suite]
    selected = [item for item in definition['cases'] if item['selection'] == 'selected']
    expected = {item['id'] for item in selected}
    coverage = read_json(output / 'functional-coverage.json')
    executed = [item['id'] for item in coverage.get('executed', [])]
    if (coverage.get('status') != 'passed' or coverage.get('suite') != suite or
            coverage.get('profile') != 'ci-functional' or coverage.get('missing') != [] or
            len(executed) != len(set(executed)) or set(executed) != expected or
            {item['id'] for item in coverage.get('selected', [])} != expected or
            len(coverage.get('selected', [])) != len(expected)):
        raise ValueError('Functional case coverage mismatch')
    signatures = lambda items: {item['id']: (item['case'], item['source']) for item in items}
    if any(signatures(coverage[key]) != signatures(selected) for key in ['selected', 'executed']):
        raise ValueError('Functional case source/name mismatch')
    excluded = [item for item in definition['cases'] if item['selection'] == 'excluded']
    if coverage.get('excluded') != excluded:
        raise ValueError('Functional excluded selection mismatch')
    result = read_json(output / RESULT_FILES[suite])
    names = [item if isinstance(item, str) else item['name'] for item in result.get('cases', [])]
    if (result.get('complete') is not True or result.get('cleanupErrors') != [] or
            result.get('failure') is not None or result.get('pageErrors') != [] or
            len(names) != len(set(names)) or set(names) != {item['case'] for item in selected}):
        raise ValueError('Incomplete functional result or browser cleanup')


def runtime_progress(suite, output):
    definition = read_json(RUNTIME_MANIFEST)['suites'][suite]
    executed = []
    for filename in definition['resultFiles']:
        if not (output / filename).exists(): continue
        result = read_json(output / filename)
        expected = {item['case']: item for item in definition['cases'] if item['resultFile'] == filename}
        names = [item if isinstance(item, str) else item['name'] for item in result.get('cases', [])]
        if len(names) != len(set(names)) or any(name not in expected for name in names):
            raise ValueError('Unknown or duplicate runtime case')
        executed += [expected[name] for name in names]
    seen = {item['id'] for item in executed}
    write_json(output / 'functional-coverage.json', {
        'profile': 'ci-functional', 'suite': suite, 'status': 'running',
        'selected': definition['cases'], 'executed': executed, 'excluded': [],
        'missing': [item['id'] for item in definition['cases'] if item['id'] not in seen]})


def interrupted(signum, frame):
    raise InterruptedError('N2 execution interrupted')


def pending_profiles(work):
    """A surviving profile without a successful close cannot be assumed safe to delete."""
    return [path for path in (work / 'tmp').iterdir()
            if path.name.startswith(('idp-n2-chrome-', 'idp-n2-linux-l05-', 'playwright'))]


def prepare(work, state):
    with deadline(min(300, remaining_job(work))):
        state['preflightStage'] = 'host'
        if platform.system() != 'Linux' or platform.machine().lower() not in ['aarch64', 'arm64']:
            raise RuntimeError('Hosted native Linux arm64 required')
        if sys.version_info < (3, 9): raise RuntimeError('Python >=3.9 required')
        state['preflightStage'] = 'docker-endpoint-and-architecture'
        verify_docker_context()
        daemon = command(['docker', 'info', '--format', '{{.OSType}}/{{.Architecture}}'])
        if daemon not in ['linux/arm64', 'linux/aarch64']: raise RuntimeError('Native arm64 daemon required')
        state['preflightStage'] = 'host-tool-versions'
        node = command(['node', '--version']); pnpm = command(['pnpm', '--version'])
        if node != 'v22.23.4' or pnpm != '10.30.1': raise RuntimeError('Frozen Node/pnpm mismatch')
        state['preflightStage'] = 'reviewed-checkout'
        checkout_sha = command(['git', 'rev-parse', 'HEAD'])
        if checkout_sha != state['owner']['source_sha']: raise RuntimeError('Checkout SHA differs from reviewed ref')
        command(['git', 'diff', '--exit-code', 'HEAD'])
        checkout_tree = command(['git', 'rev-parse', 'HEAD^{tree}'])
        js = """const {createRequire}=require('node:module'); const r=createRequire(process.cwd()+'/scripts/n2-ci/package.json');
const {chromium}=r('playwright'); const p=r('playwright/package.json'); const fs=require('node:fs'),path=require('node:path');
const playwrightRequire=createRequire(r.resolve('playwright/package.json'));
const browsers=JSON.parse(fs.readFileSync(path.join(path.dirname(playwrightRequire.resolve('playwright-core/package.json')),'browsers.json'),'utf8'));
console.log(JSON.stringify({version:p.version,browser:browsers.browsers.find(b=>b.name==='chromium'),executable:chromium.executablePath()}));"""
        state['preflightStage'] = 'owned-full-chromium'
        browser = json.loads(command(['node', '-e', js]))
        if (browser['version'] != '1.64.1' or browser['browser']['revision'] != '1248' or
                browser['browser']['browserVersion'] != '156.0.8078.4'):
            raise RuntimeError('Frozen browser package/revision mismatch')
        executable = Path(browser['executable']).resolve()
        if not executable.is_relative_to(work / 'browsers') or not executable.is_file():
            raise RuntimeError('Installed owned full Chromium required')
        browser['binarySha256'] = sha256(executable)
        browser['channel'] = 'chromium'; browser['headless'] = True
        browser['actualVersion'] = command([str(executable), '--version'])
        if '156.0.8078.4' not in browser['actualVersion'].split(): raise RuntimeError('Installed browser version mismatch')
        versions = {name: command(args) for name, args in {
            'docker': ['docker', '--version'], 'buildx': ['docker', 'buildx', 'version'],
            'buildkit': ['docker', 'buildx', 'inspect'], 'kernel': ['uname', '-a']}.items()}
        environment = {'scope': 'CI-FUNC-ARM64-01', 'source': state['owner'], 'checkoutSha': checkout_sha,
                       'checkoutTree': checkout_tree, 'node': node, 'pnpm': pnpm,
                       'python': platform.python_version(), 'os': platform.platform(), 'arch': platform.machine(),
                       'runnerArch': os.environ.get('RUNNER_ARCH'), 'imageVersion': os.environ.get('ImageVersion'),
                       'runnerVersion': os.environ.get('ACTIONS_RUNNER_VERSION'), 'browser': browser, 'tools': versions,
                       'cpuCount': os.cpu_count(), 'diskFreeBytes': shutil.disk_usage(work).free,
                       'memory': Path('/proc/meminfo').read_text(), 'baseImages': BASES}
        if os.environ.get('RUNNER_ARCH') != 'ARM64': raise RuntimeError('runner.arch is not ARM64')
        write_json(work / 'evidence/environment.json', environment)
        state['playwright'] = str(ROOT / 'scripts/n2-ci/node_modules/playwright/index.mjs')
        state['browserExecutable'] = str(executable)
    with deadline(min(1800, remaining_job(work))):
        state['preflightStage'] = 'frozen-image-inputs'
        for name, ref in BASES.items():
            result = command(['docker', 'pull', '--platform', 'linux/arm64', ref], timeout=180)
            path = work / f'evidence/pull-{name}.log'; path.write_text(result + '\n')
        build = work / 'evidence/build'
        state['preflightStage'] = 'release-default-feature-build'
        command([sys.executable, '-B', 'scripts/build_management_n2_linux.py',
                 '--node-image', BASES['node'], '--rust-image', BASES['rust'],
                 '--runtime-image', BASES['runtime'], '--build-jobs', '2', '--output', str(build)], timeout=1800)
        images = read_json(build / 'image-summary.json')['images']
        if any(item.get('architecture') != 'arm64' or item.get('os') != 'linux' for item in images.values()):
            raise RuntimeError('Built image platform mismatch')
        state['runtime'] = images['runtime']['id']; state['prepare'] = images['prepare']['id']
        build_log = (build / 'build-runtime.log').read_text()
        if not re.search(r'\brustc 1\.93\.0\b', build_log) or not re.search(r'\bv22\.23\.4\b', build_log):
            raise RuntimeError('Actual build tool versions missing or mismatched')
    write_json(work / 'evidence/tool-manifest.json', tool_manifest())
    state['prepared'] = True


def run_suites(work, state, suites=SUITES):
    if not state.get('prepared') or state.get('failedPhase'):
        raise RuntimeError('Prepare phase did not complete successfully; use a fresh run attempt')
    failed = False
    records = []
    for suite in suites:
        if suite not in SUITES: raise ValueError('Unknown suite')
        if remaining_job(work) < 480:
            records.append({'suite': suite, 'status': 'not_executed', 'reason': 'JobDeadlineReserve'})
            failed = True; break
        output = work / 'evidence' / suite; output.mkdir(parents=True, exist_ok=False)
        record = {'suite': suite, 'profile': 'ci-functional', 'status': 'running', 'exitCode': 1,
                  'headed': False, 'channel': 'chromium', 'viewport': [1440, 1000],
                  'freshFixture': True, 'n2Layout': False, 'commands': []}
        write_json(output / 'execution.json', record)
        if suite in ['gates', 'n2_mac']: runtime_progress(suite, output)
        fixture = None; start = time.monotonic(); stop = False
        secrets = read_json(work / 'secrets.json') if (work / 'secrets.json').exists() else []
        try:
            # Reserve 45 seconds inside the eight-minute suite ceiling for cleanup.
            with deadline(435):
                fixture = Fixture.create(state['runtime'], state['prepare'], BASES['postgres'])
                with (work / 'fixtures.jsonl').open('a') as inventory:
                    inventory.write(str(fixture.directory / 'state.json') + '\n')
                fixture.prepare()
                secrets += [fixture.state.get(key) for key in ['password', 'db_password', 'db_uri'] if fixture.state.get(key)]
                write_json(work / 'secrets.json', sorted(set(secrets)))
                env = {**os.environ, 'IDP_UI_TEST_FIXTURE': str(fixture.directory / 'state.json'),
                       'IDP_UI_PLAYWRIGHT_PATH': state['playwright'], 'IDP_UI_BROWSER_EXECUTABLE': state['browserExecutable'],
                       'IDP_UI_OUTPUT_DIR': str(output), 'IDP_UI_HEADED': '0', 'IDP_UI_N2_LAYOUT': '0'}
                commands = [[sys.executable, '-B', 'scripts/check_management_n2_linux.py', '--fixture', env['IDP_UI_TEST_FIXTURE'], '--output', str(output / 'runtime')],
                            ['node', 'scripts/check_management_n2_linux_restart.mjs']] if suite == 'gates' else [['node', 'scripts/check_management_' + suite + '.mjs']]
                for args in commands:
                    result = run_bounded(args, cwd=ROOT, env=env, timeout=435)
                    (fixture.directory / 'checker.stdout').write_text(result.stdout)
                    (fixture.directory / 'checker.stderr').write_text(result.stderr)
                    record['commands'].append({'tool': next(a for a in args if a.startswith('scripts/')),
                                               'exitCode': result.returncode, 'diagnostic': checker_diagnostic(result.stderr)})
                    if suite in ['gates', 'n2_mac']: runtime_progress(suite, output)
                    if result.returncode: raise RuntimeError('Acceptance checker failed')
                validate_coverage(suite, output)
                record.update(status='passed', exitCode=0)
        except BaseException as error:
            record.update(status='failed', error=type(error).__name__)
            failed = True
            stop = isinstance(error, (InterruptedError, KeyboardInterrupt, subprocess.TimeoutExpired, TimeoutError))
            coverage_path = output / 'functional-coverage.json'
            if coverage_path.exists():
                coverage = read_json(coverage_path)
                coverage.update(status='failed', failure=type(error).__name__)
                write_json(coverage_path, coverage)
        finally:
            # Gather secrets even if preparation failed partway; never publish raw fixture files.
            if fixture:
                secrets += [fixture.state.get(key) for key in ['password', 'db_password', 'db_uri'] if fixture.state.get(key)]
                write_json(work / 'secrets.json', sorted(set(secrets)))
                try:
                    with deadline(max(1, 480 - (time.monotonic() - start))):
                        fixture = Fixture.load(fixture.directory / 'state.json')
                        from run_management_n2_linux import profile_recovery_required
                        retained = profile_recovery_required(output, fixture.directory)
                        if pending_profiles(work):
                            record['cleanup'] = {'errors': [{'resource': 'browser-profile', 'error': 'ExitUnconfirmed'}],
                                                 'privateDirectoryRemoved': False}
                            raise RuntimeError('Browser profile exit unconfirmed; fixture dependencies retained')
                        record['cleanup'] = fixture.cleanup(preserve_private=retained)
                        if retained: record['cleanup']['errors'].append({'resource': 'browser-profile', 'error': 'PrivateRecoveryRequired'})
                        if record['cleanup']['errors']: raise RuntimeError('Fixture cleanup failed')
                except BaseException as error:
                    record.update(status='failed', exitCode=1, cleanupError=type(error).__name__)
                    failed = True; stop = True
            record['durationSeconds'] = round(time.monotonic() - start, 2)
            write_json(output / 'execution.json', record)
            records.append(record)
            write_json(work / 'evidence/suite-summary.json', {'suites': records, 'complete': len(records) == len(suites) and not failed})
        if record['status'] != 'passed': failed = True
        # An unexplained checker failure may be a security assertion: fail closed until reviewed.
        if stop or record['status'] != 'passed': break
    seen = {record['suite'] for record in records}
    reason = next((record.get('reason') for record in records if record.get('reason')), 'PredecessorFailedOrInterrupted')
    records += [{'suite': suite, 'status': 'not_executed', 'reason': reason} for suite in suites if suite not in seen]
    write_json(work / 'evidence/suite-summary.json', {'suites': records, 'complete': not failed and len(seen) == len(suites)})
    state['suitesComplete'] = len(records) == len(SUITES) and not failed
    return not failed and len(records) == len(suites)


def reap_processes(work):
    errors = []
    path = work / 'processes.jsonl'
    if not path.exists(): return errors
    for item in [json.loads(line) for line in path.read_text().splitlines()]:
        pid = item['pid']; identity = item['startTicks']
        current = process_identity(pid)
        if current is None:
            if item.get('pgid'):
                try: os.killpg(item['pgid'], 0)
                except ProcessLookupError: pass
                else: errors.append({'resource': 'process-group', 'error': 'LeaderExitedGroupUnknown'})
            continue
        if identity is None:
            errors.append({'resource': 'process', 'error': 'IdentityUnavailable'}); continue
        if current != identity: continue  # Original process exited; PID was reused.
        for signum in [signal.SIGTERM, signal.SIGKILL]:
            try: os.kill(pid, signum)
            except ProcessLookupError: break
            end = time.monotonic() + 1
            while process_identity(pid) == identity and time.monotonic() < end: time.sleep(.02)
            if process_identity(pid) != identity: break
        if process_identity(pid) == identity:
            errors.append({'resource': 'process', 'error': 'ExitUnconfirmed'})
    return errors


def finalize(work, output, state):
    errors = []
    with deadline(540):
        errors += reap_processes(work)
        if pending_profiles(work):
            errors.append({'resource': 'browser-profile', 'error': 'ExitUnconfirmed'})
        if not errors:
            inventory = work / 'fixtures.jsonl'
            for raw in inventory.read_text().splitlines() if inventory.exists() else []:
                path = Path(raw)
                if not path.is_relative_to(work / 'tmp') or path.parent.parent != work / 'tmp':
                    errors.append({'resource': 'fixture', 'error': 'PathOwnershipMismatch'}); continue
                if not path.parent.exists(): continue
                try:
                    fixture = Fixture.load(path)
                    cleanup = fixture.cleanup()
                    if cleanup['errors']: errors.extend(cleanup['errors'])
                except Exception as error: errors.append({'resource': 'fixture', 'error': type(error).__name__})
        # Final label readback is required even after cleanup; a failed daemon is not absence.
        if state.get('prepared') or (work / 'fixtures.jsonl').exists():
            identity = ci_identity()
            filters = [part for key, value in identity.items() for part in ['--filter', f'label=idp.n2-linux.ci.{key}={value}']]
            for kind in ['container', 'network', 'volume']:
                try:
                    args = ['docker', kind, 'ls', *( ['-a'] if kind == 'container' else []), *filters, '--format', '{{.ID}}' if kind == 'container' else '{{.Name}}']
                    if command(args): errors.append({'resource': kind, 'error': 'OwnedObjectsRemain'})
                except Exception as error: errors.append({'resource': kind, 'error': type(error).__name__})
        secrets = read_json(work / 'secrets.json') if (work / 'secrets.json').exists() else []
        # Public contains only files produced here, not caller-provided leftovers.
        for child in output.iterdir():
            if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)
            else: child.unlink()
        errors += publish(work / 'evidence', output, secrets, work)
        if state.get('suitesComplete'):
            try: validate_suite_evidence(output, state['owner'])
            except (ValueError, OSError, KeyError, TypeError) as error:
                errors.append({'resource': 'suite-evidence', 'error': type(error).__name__})
        if not errors:
            for name in ['tmp', 'evidence', 'browsers']:
                if (work / name).exists():
                    try: shutil.rmtree(work / name)
                    except OSError as error: errors.append({'resource': name, 'error': type(error).__name__})
            if not errors:
                for name in ['secrets.json', 'fixtures.jsonl', 'processes.jsonl']:
                    try: (work / name).unlink(missing_ok=True)
                    except OSError as error: errors.append({'resource': name, 'error': type(error).__name__})
        passed = bool(state.get('prepared') and state.get('suitesComplete') and not state.get('failedPhase') and
                      not errors and os.environ.get('IDP_N2_JOB_STATUS') == 'success')
        summary = {'scope': 'CI-FUNC-ARM64-01', 'source': state['owner'],
                   'status': 'passed' if passed else 'failed', 'actualExecution': bool(state.get('suitesComplete')),
                   'cleanup': 'confirmed' if not errors else 'failed_or_unknown', 'errors': errors,
                   'excluded': ['zoom', 'VoiceOver', 'visual-acceptance', 'M1-03–06'],
                   'artifactRetentionDaysRequested': 30,
                   'artifactEffectiveExpiry': None, 'expiryVerification': 'pending_first_actual_run_review',
                   'evidenceComplete': passed}
        write_json(output / 'final-summary.json', summary)
        # A failed functional run still has useful sanitized evidence. Attest its
        # exact files so the workflow can retain it without treating exit 1 as success.
        for path in output.rglob('*'):
            if path.is_symlink() or path.is_file() and not public_name(path):
                raise ValueError('Public evidence inventory is unsafe')
            if path.is_file():
                original = path.read_text()
                sanitized = safe_text(original, secrets, work)
                if sanitized != original: path.write_text(sanitized)
        write_json(output / 'publication.json', {'schemaVersion': 1, 'sanitized': True,
                   'files': {str(path.relative_to(output)): sha256(path) for path in sorted(output.rglob('*')) if path.is_file()}})
        state['finalized'] = passed
        return passed


def validate_suite_evidence(output, owner):
    summary = read_json(output / 'suite-summary.json')
    records = summary.get('suites', [])
    if (summary.get('complete') is not True or len(records) != len(SUITES) or
            [item.get('suite') for item in records] != SUITES):
        raise ValueError('Eight complete suite records required')
    for record in records:
        suite = record['suite']
        execution = read_json(output / suite / 'execution.json')
        cleanup = execution.get('cleanup', {})
        expected_commands = (['scripts/check_management_n2_linux.py', 'scripts/check_management_n2_linux_restart.mjs']
                             if suite == 'gates' else ['scripts/check_management_' + suite + '.mjs'])
        commands = execution.get('commands', [])
        if (record != execution or execution.get('status') != 'passed' or execution.get('exitCode') != 0 or
                execution.get('profile') != 'ci-functional' or execution.get('headed') is not False or
                execution.get('channel') != 'chromium' or execution.get('viewport') != [1440, 1000] or
                execution.get('n2Layout') is not False or execution.get('freshFixture') is not True or
                cleanup.get('errors') != [] or cleanup.get('privateDirectoryRemoved') is not True or
                execution.get('cleanupError') or
                [item.get('tool') for item in commands] != expected_commands or
                any(item.get('exitCode') != 0 for item in commands)):
            raise ValueError('Incomplete suite execution or cleanup')
        validate_coverage(suite, output / suite, persist_runtime=False)
    environment = read_json(output / 'environment.json')
    if (environment.get('source') != owner or environment.get('checkoutSha') != owner['source_sha'] or
            environment.get('scope') != 'CI-FUNC-ARM64-01' or
            read_json(output / 'tool-manifest.json') != tool_manifest() or
            read_json(output / 'build/source-manifest.json').get('git_head') != owner['source_sha']):
        raise ValueError('Evidence source identity mismatch')
    for relative in ['environment.json', 'tool-manifest.json', 'build/source-manifest.json',
                     'build/image-summary.json', 'build/build-runtime.log', 'build/build-prepare.log',
                     *['build/input-' + name + '-image.log' for name in ['node', 'rust', 'runtime']],
                     'gates/runtime/served-assets.json',
                     *['gates/runtime/' + name + '-runtime.txt' for name in ['enabled', 'disabled', 'fixed', 'choose']],
                     *['pull-' + name + '.log' for name in BASES]]:
        if not (output / relative).is_file():
            raise ValueError('Required preparation evidence missing')


def validate_publication(output):
    if (output / 'publication.json').is_symlink(): raise ValueError('Public evidence seal symlink rejected')
    manifest = read_json(output / 'publication.json')
    if (not isinstance(manifest, dict) or type(manifest.get('schemaVersion')) is not int or
            manifest['schemaVersion'] != 1 or manifest.get('sanitized') is not True or
            not isinstance(manifest.get('files'), dict) or not manifest['files']):
        raise ValueError('Invalid public evidence seal')
    files = manifest['files']
    for relative, digest in files.items():
        path = PurePosixPath(relative)
        if (path.is_absolute() or path.as_posix() != relative or not path.parts or
                any(part in ['.', '..'] for part in path.parts) or relative == 'publication.json' or
                not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)):
            raise ValueError('Invalid public evidence path/hash')
    actual = set()
    for path in output.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Unsafe public evidence entry')
        if path.is_file():
            if not public_name(path): raise ValueError('Artifact whitelist mismatch')
            safe_text(path.read_text(encoding='utf-8'))
            if path.name != 'publication.json' or path.parent != output:
                actual.add(path.relative_to(output).as_posix())
    if actual != set(files) or any(sha256(output / relative) != digest for relative, digest in files.items()):
        raise ValueError('Public evidence inventory/hash mismatch')


def verify(work, output, state):
    summary = read_json(output / 'final-summary.json')
    if (not state.get('finalized') or summary.get('status') != 'passed' or
            summary.get('source') != state.get('owner') or summary.get('evidenceComplete') is not True or
            summary.get('actualExecution') is not True or summary.get('cleanup') != 'confirmed' or summary.get('errors') != [] or
            os.environ.get('IDP_N2_JOB_STATUS') != 'success' or
            os.environ.get('IDP_N2_ARTIFACT_OUTCOME') != 'success' or
            not os.environ.get('IDP_N2_ARTIFACT_ID', '').isdigit()):
        raise RuntimeError('Functional/cleanup/evidence/upload gate failed')
    validate_publication(output)
    validate_suite_evidence(output, state['owner'])
    step_summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if step_summary:
        artifact_id = os.environ['IDP_N2_ARTIFACT_ID']
        artifact_url = os.environ.get('IDP_N2_ARTIFACT_URL', '')
        digest = os.environ.get('IDP_N2_ARTIFACT_DIGEST', '')
        # Action outputs are metadata; validate before including them in Markdown.
        if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+/artifacts/[0-9]+', artifact_url):
            raise ValueError('Artifact URL mismatch')
        if not re.fullmatch(r'[a-f0-9]{64}', digest): raise ValueError('Artifact digest missing')
        with Path(step_summary).open('a') as stream:
            stream.write(f'N2 functional execution/cleanup passed. Artifact [{artifact_id}]({artifact_url}), SHA256 `{digest}`.\n\n')
            stream.write('Requested retention: 30 days. Actual expires_at requires first-run review before archival sign-off.\n')


def owned_paths(work, output, runner_temp, identity):
    # Accept the runner's spelling (e.g. macOS /var) but reject symlinks below it.
    root = Path(os.path.abspath(runner_temp))
    work = Path(os.path.abspath(work)); output = Path(os.path.abspath(output))
    expected_work = root / f"idp-n2-ci-{identity['run_id']}-{identity['run_attempt']}"
    expected_output = root / 'n2-public' / identity['run_id'] / identity['run_attempt']
    if work != expected_work or output != expected_output:
        raise ValueError('CI paths do not match this run and attempt')
    for path in [work, output]:
        for candidate in [path, *path.parents]:
            if candidate == root: break
            if candidate.is_symlink(): raise ValueError('CI path ancestor symlink rejected')
    for name in ['tmp', 'evidence', 'browsers', 'job-state.json', 'job-started-at',
                 'secrets.json', 'fixtures.jsonl', 'processes.jsonl']:
        for candidate in [work / name, work / (name + '.next')]:
            if candidate.is_symlink(): raise ValueError('CI private path symlink rejected')
    return work.resolve(), output.resolve()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'run', 'finalize', 'verify'])
    parser.add_argument('--work', required=True, type=Path); parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if os.environ.get('GITHUB_ACTIONS') != 'true': parser.error('Actual CI entry requires an explicit GitHub Actions runner')
    os.environ['IDP_UI_PROFILE'] = 'ci-functional'
    identity = ci_identity()
    try: work, output = owned_paths(args.work, args.output, os.environ['RUNNER_TEMP'], identity)
    except ValueError as error: parser.error(str(error))
    os.umask(0o077)
    work.mkdir(parents=True, exist_ok=True, mode=0o700); output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if work.stat().st_mode & 0o077 or output.stat().st_mode & 0o077:
        parser.error('CI private/public roots require owner-only permissions')
    os.environ['IDP_UI_PROFILE'] = 'ci-functional'
    # Select this invocation's endpoint, never mutate Docker's global context.
    for name, value in [('DOCKER_CONTEXT', 'default'), ('DOCKER_HOST', 'unix:///var/run/docker.sock')]:
        if os.environ.get(name) not in [None, '', value]: parser.error('Conflicting Docker endpoint')
        os.environ[name] = value
    state_path = work / 'job-state.json'
    state = read_json(state_path) if state_path.exists() else {'owner': identity}
    if state.get('owner') != identity: parser.error('CI state belongs to a different run/ref')
    if args.phase != 'verify':
        (work / 'tmp').mkdir(exist_ok=True, mode=0o700)
        (work / 'evidence').mkdir(exist_ok=True, mode=0o700)
    os.environ['TMPDIR'] = str(work / 'tmp'); tempfile.tempdir = None
    browser_root = str(work / 'browsers')
    if os.environ.get('PLAYWRIGHT_BROWSERS_PATH') not in [None, '', browser_root]:
        parser.error('Browser installation belongs to a different root')
    os.environ['PLAYWRIGHT_BROWSERS_PATH'] = browser_root
    os.environ['IDP_N2_PROCESS_REGISTRY'] = str(work / 'processes.jsonl')
    for signum in [signal.SIGINT, signal.SIGTERM]: signal.signal(signum, interrupted)
    success = False
    try:
        if args.phase in ['prepare', 'run'] and state.get('failedPhase'):
            raise RuntimeError('Failed run attempt requires a fresh run attempt and isolated data')
        if args.phase == 'prepare':
            state.update(prepared=False, suitesComplete=False, finalized=False)
            prepare(work, state); success = True
        elif args.phase == 'run': success = run_suites(work, state)
        elif args.phase == 'finalize': success = finalize(work, output, state)
        else: verify(work, output, state); success = True
    except BaseException as error:
        # Exception text can include subprocess args/configuration. Keep only its class publicly.
        write_json(work / 'evidence/failure.json', {'phase': args.phase, 'status': 'failed',
                   'stage': state.get('preflightStage') if args.phase == 'prepare' else args.phase,
                   'error': type(error).__name__})
        state['failedPhase'] = args.phase
        if args.phase == 'finalize':
            state['finalized'] = False
            write_json(output / 'final-summary.json', {'status': 'failed', 'cleanup': 'unknown',
                       'evidenceComplete': False, 'error': type(error).__name__})
    finally:
        write_json(state_path, state)
    return 0 if success else 1


if __name__ == '__main__': raise SystemExit(main())
