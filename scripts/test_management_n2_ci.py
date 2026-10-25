"""Offline N2 CI driver checks. No Docker, browser, PG, HTTP or product execution."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest
from unittest.mock import Mock, patch

import run_management_n2_ci as ci


class DriverTests(unittest.TestCase):
    def setUp(self):
        original_tempdir = tempfile.tempdir
        self.addCleanup(setattr, tempfile, 'tempdir', original_tempdir)
        self.temporary = tempfile.TemporaryDirectory(prefix='n2-ci-offline-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / 'idp-n2-ci-123-1'
        self.output = self.root / 'n2-public/123/1'
        for path in [self.work / 'tmp', self.work / 'evidence', self.work / 'browsers', self.output]:
            path.mkdir(parents=True, mode=0o700)
        self.work.chmod(0o700)
        self.output.chmod(0o700)
        (self.work / 'job-started-at').write_text(str(time.time()))
        self.owner = {'run_id': '123', 'run_attempt': '1', 'job': 'functional-arm64', 'source_sha': 'a' * 40}
        self.state = {'owner': self.owner, 'prepared': True, 'suitesComplete': True,
                      'runtime': 'sha256:runtime', 'prepare': 'sha256:prepare',
                      'playwright': '/not-installed/playwright/index.mjs',
                      'browserExecutable': '/not-installed/chromium'}
        environment = {'IDP_UI_PROFILE': 'ci-functional', 'IDP_N2_JOB_STATUS': 'success',
                       'IDP_N2_ARTIFACT_OUTCOME': 'success', 'IDP_N2_ARTIFACT_ID': '12345',
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                       'GITHUB_JOB': 'functional-arm64', 'GITHUB_SHA': 'a' * 40,
                       'PATH': os.environ.get('PATH', ''), 'HOME': os.environ.get('HOME', '')}
        environment_patch = patch.dict(os.environ, environment, clear=True)
        environment_patch.start(); self.addCleanup(environment_patch.stop)
        for name in ['command', 'run_bounded']:
            guard = patch.object(ci, name, side_effect=AssertionError('External operation forbidden in offline tests'))
            setattr(self, name, guard.start()); self.addCleanup(guard.stop)
        fixture_patch = patch.object(ci, 'Fixture')
        self.fixtures = fixture_patch.start(); self.addCleanup(fixture_patch.stop)
        identity_patch = patch.object(ci, 'ci_identity', return_value=self.owner)
        identity_patch.start(); self.addCleanup(identity_patch.stop)
        reaper_patch = patch.object(ci, 'reap_processes', return_value=[])
        self.reaper = reaper_patch.start(); self.addCleanup(reaper_patch.stop)

    def write(self, relative, value):
        ci.write_json(self.work / 'evidence' / relative, value)

    def final_summary(self):
        return ci.read_json(self.output / 'final-summary.json')

    def allow_empty_docker_readback(self):
        self.command.side_effect = None; self.command.return_value = ''

    def write_runtime_results(self, suite):
        definition = ci.read_json(ci.RUNTIME_MANIFEST)['suites'][suite]
        for filename in definition['resultFiles']:
            ci.write_json(self.output / filename, {
                'complete': True, 'cleanupErrors': [],
                'cases': [c['case'] for c in definition['cases'] if c['resultFile'] == filename],
            })
        return definition

    def functional_result(self, suite):
        definition = ci.read_json(ci.MANIFEST)['suites'][suite]
        selected = [c for c in definition['cases'] if c['selection'] == 'selected']
        return {'suite': suite, 'profile': 'ci-functional', 'status': 'passed',
                'selected': copy.deepcopy(selected), 'executed': copy.deepcopy(selected), 'missing': [],
                'excluded': [copy.deepcopy(c) for c in definition['cases'] if c['selection'] == 'excluded']}

    def write_functional_results(self, suite, output=None):
        output = output or self.output
        result = self.functional_result(suite)
        ci.write_json(output / 'functional-coverage.json', result)
        ci.write_json(output / ci.RESULT_FILES[suite], {
            'cases': [item['case'] for item in result['selected']], 'pageErrors': [],
            'complete': True, 'cleanupErrors': [], 'failure': None})
        return result

    def complete_mock_evidence(self, output):
        records = []
        for suite in ci.SUITES:
            directory = output / suite
            directory.mkdir(parents=True, exist_ok=True)
            if suite in ['gates', 'n2_mac']:
                definition = ci.read_json(ci.RUNTIME_MANIFEST)['suites'][suite]
                for filename in definition['resultFiles']:
                    ci.write_json(directory / filename, {
                        'complete': True, 'cleanupErrors': [],
                        'cases': [c['case'] for c in definition['cases'] if c['resultFile'] == filename]})
                ci.validate_coverage(suite, directory)
            else:
                self.write_functional_results(suite, directory)
            tools = (['scripts/check_management_n2_linux.py', 'scripts/check_management_n2_linux_restart.mjs']
                     if suite == 'gates' else ['scripts/check_management_' + suite + '.mjs'])
            record = {'suite': suite, 'status': 'passed', 'exitCode': 0, 'profile': 'ci-functional',
                      'headed': False, 'channel': 'chromium', 'viewport': [1440, 1000],
                      'n2Layout': False, 'freshFixture': True,
                      'commands': [{'tool': tool, 'exitCode': 0} for tool in tools],
                      'cleanup': {'errors': [], 'privateDirectoryRemoved': True}}
            records.append(record)
            ci.write_json(directory / 'execution.json', record)
        ci.write_json(output / 'suite-summary.json', {'suites': records, 'complete': True})
        for relative in ['environment.json', 'tool-manifest.json', 'build/source-manifest.json',
                         'build/image-summary.json', 'build/build-runtime.log', 'build/build-prepare.log',
                         *['build/input-' + name + '-image.log' for name in ['node', 'rust', 'runtime']],
                         'gates/runtime/served-assets.json',
                         *['gates/runtime/' + name + '-runtime.txt' for name in ['enabled', 'disabled', 'fixed', 'choose']],
                         *['pull-' + name + '.log' for name in ci.BASES]]:
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}' if path.suffix == '.json' else 'OFFLINE MOCK; no real operation\n')
        ci.write_json(output / 'environment.json', {
            'source': self.owner, 'checkoutSha': self.owner['source_sha'], 'scope': 'CI-FUNC-ARM64-01'})
        ci.write_json(output / 'tool-manifest.json', ci.tool_manifest())
        ci.write_json(output / 'build/source-manifest.json', {'git_head': self.owner['source_sha']})

    def seal_mock_publication(self):
        ci.write_json(self.output / 'publication.json', {'schemaVersion': 1, 'sanitized': True,
            'files': {path.relative_to(self.output).as_posix(): ci.sha256(path)
                      for path in self.output.rglob('*') if path.is_file() and path.name != 'publication.json'}})

    def complete_mock_publication(self):
        self.complete_mock_evidence(self.output)
        self.state['finalized'] = True
        ci.write_json(self.output / 'final-summary.json', {
            'status': 'passed', 'source': self.owner, 'evidenceComplete': True,
            'actualExecution': True, 'cleanup': 'confirmed', 'errors': []})
        self.seal_mock_publication()

    def fake_fixture(self):
        directory = self.work / 'tmp/idp-ui-b-offline'
        directory.mkdir()
        (directory / 'state.json').write_text('{}')
        fixture = Mock(directory=directory, state={'password': 'synthetic-password', 'db_password': 'synthetic-db'})
        fixture.cleanup.return_value = {'errors': [], 'objects': [], 'privateDirectoryRemoved': True}
        self.fixtures.create.return_value = fixture
        self.fixtures.load.return_value = fixture
        return fixture

    @contextlib.contextmanager
    def mocked_prepare(self, changes=None):
        """Synthetic metadata and dummy bytes only; never execute a browser or build."""
        changes = changes or {}
        work = self.work.resolve()
        executable = work / 'browsers/chromium-offline'
        executable.write_bytes(b'offline dummy browser bytes; never executable\n')
        selected_executable = executable
        if changes.get('binary') == 'outside':
            selected_executable = self.root.resolve() / 'outside-offline-browser'
            selected_executable.write_bytes(b'offline outside path')
        elif changes.get('binary') == 'missing':
            selected_executable = work / 'browsers/missing-offline-browser'
        browser = {'version': changes.get('playwright', '1.64.1'),
                   'browser': {'revision': changes.get('revision', '1248'),
                               'browserVersion': changes.get('browserManifestVersion', '156.0.8078.4')},
                   'executable': str(selected_executable)}

        def fake_command(args, **kwargs):
            if args[:2] == ['docker', 'info']: return changes.get('daemon', 'linux/arm64')
            if args == ['node', '--version']: return changes.get('node', 'v22.23.4')
            if args == ['pnpm', '--version']: return changes.get('pnpm', '10.30.1')
            if args == ['git', 'rev-parse', 'HEAD']: return changes.get('checkout', 'a' * 40)
            if args == ['git', 'rev-parse', 'HEAD^{tree}']: return 'b' * 40
            if args[:2] == ['git', 'diff']:
                if changes.get('dirty'): raise subprocess.CalledProcessError(1, 'offline dirty tree')
                return ''
            if args[:2] == ['node', '-e']: return json.dumps(browser)
            if args == [str(selected_executable), '--version']:
                return changes.get('browserVersion', 'Chromium 156.0.8078.4 (offline mock)')
            if args[:2] == ['docker', 'pull']:
                self.assertEqual(args[2:4], ['--platform', 'linux/arm64'])
                self.assertIn(args[4], ci.BASES.values())
                self.assertEqual(kwargs.get('timeout'), 180)
                return 'offline mock pull metadata; no registry operation'
            if 'scripts/build_management_n2_linux.py' in args:
                if changes.get('buildTimeout'): raise TimeoutError('offline bounded build timeout')
                self.assertEqual(kwargs.get('timeout'), 1800)
                self.assertEqual(args[args.index('--build-jobs') + 1], '2')
                for option, name in [('--node-image', 'node'), ('--rust-image', 'rust'), ('--runtime-image', 'runtime')]:
                    self.assertEqual(args[args.index(option) + 1], ci.BASES[name])
                output = Path(args[args.index('--output') + 1])
                ci.write_json(output / 'image-summary.json', {'images': {
                    name: {'id': 'sha256:offline-' + name,
                           'architecture': changes.get('imageArchitecture', 'arm64'),
                           'os': changes.get('imageOs', 'linux')}
                    for name in ['runtime', 'prepare']}})
                (output / 'build-runtime.log').write_text(changes.get(
                    'buildLog', 'OFFLINE MOCK: no build was run\nrustc 1.93.0 (offline marker)\nv22.23.4\n'))
                return 'offline mock build response'
            if args[:1] in [['docker'], ['uname']]: return 'offline mock tool version'
            raise AssertionError('Unexpected external command in prepare test: ' + repr(args))

        original_read_text = Path.read_text
        def fake_read_text(path, *args, **kwargs):
            if path == Path('/proc/meminfo'): return 'OFFLINE MOCK MemTotal: 8000000 kB\n'
            return original_read_text(path, *args, **kwargs)

        state = copy.deepcopy(self.state)
        for key in ['prepared', 'suitesComplete']: state.pop(key, None)
        self.command.reset_mock(); self.command.side_effect = fake_command
        with contextlib.ExitStack() as stack:
            docker_context = stack.enter_context(patch.object(ci, 'verify_docker_context'))
            stack.enter_context(patch.object(ci.platform, 'system', return_value=changes.get('system', 'Linux')))
            stack.enter_context(patch.object(ci.platform, 'machine', return_value=changes.get('machine', 'aarch64')))
            stack.enter_context(patch.object(ci.platform, 'platform', return_value='offline mock Linux arm64'))
            stack.enter_context(patch.object(ci, 'tool_manifest', return_value={'offline-only': 'synthetic hash'}))
            stack.enter_context(patch.object(Path, 'read_text', new=fake_read_text))
            stack.enter_context(patch.dict(os.environ, {'RUNNER_ARCH': changes.get('runnerArch', 'ARM64')}))
            budgets = stack.enter_context(patch.object(ci, 'deadline', wraps=ci.deadline))
            yield work, state, executable, docker_context, budgets

    def test_prepare_accepts_only_complete_matching_mocked_environment(self):
        with self.mocked_prepare() as (work, state, executable, docker_context, budgets):
            ci.prepare(work, state)
            self.assertTrue(state['prepared'])
            docker_context.assert_called_once()
            self.assertEqual(state['runtime'], 'sha256:offline-runtime')
            environment = ci.read_json(work / 'evidence/environment.json')
            self.assertEqual(environment['checkoutSha'], 'a' * 40)
            self.assertEqual(environment['checkoutTree'], 'b' * 40)
            self.assertEqual(environment['browser']['binarySha256'], hashlib.sha256(executable.read_bytes()).hexdigest())
            self.assertEqual(environment['browser']['channel'], 'chromium')
            self.assertTrue(environment['browser']['headless'])
            self.assertIn('offline mock', environment['browser']['actualVersion'])
            self.assertLessEqual(budgets.call_args_list[0].args[0], 300)
            self.assertLessEqual(budgets.call_args_list[1].args[0], 1800)
            self.assertEqual(len([c for c in self.command.call_args_list if c.args[0][:2] == ['docker', 'pull']]), len(ci.BASES))
            self.run_bounded.assert_not_called()
            self.fixtures.create.assert_not_called()

    def test_browser_metadata_resolves_core_from_nonhoisted_playwright(self):
        with self.mocked_prepare() as (work, state, *_):
            ci.prepare(work, state)
        script = next(call.args[0][2] for call in self.command.call_args_list
                      if call.args[0][:2] == ['node', '-e'])
        project = self.root / 'pnpm-project'
        package = project / 'scripts/n2-ci'
        modules = package / 'node_modules'
        playwright = modules / '.pnpm/playwright@1.64.1/node_modules/playwright'
        core = modules / '.pnpm/playwright-core@1.64.1/node_modules/playwright-core'
        for path in [playwright, core]: path.mkdir(parents=True)
        ci.write_json(package / 'package.json', {'name': 'offline-synthetic-tooling'})
        ci.write_json(playwright / 'package.json', {'name': 'playwright', 'version': '1.64.1', 'main': 'index.js'})
        (playwright / 'index.js').write_text("exports.chromium = {executablePath: () => '/synthetic/owned/chrome'};\n")
        ci.write_json(core / 'package.json', {'name': 'playwright-core', 'version': '1.64.1'})
        manifest = {'name': 'chromium', 'revision': '1248', 'browserVersion': '156.0.8078.4'}
        ci.write_json(core / 'browsers.json', {'browsers': [manifest]})
        (modules / 'playwright').symlink_to(playwright, target_is_directory=True)
        (playwright.parent / 'playwright-core').symlink_to(core, target_is_directory=True)
        direct = subprocess.run(['node', '-e',
            "require('node:module').createRequire(process.cwd()+'/scripts/n2-ci/package.json').resolve('playwright-core/package.json')"],
            cwd=project, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(direct.returncode, 0)
        self.assertIn('MODULE_NOT_FOUND', direct.stderr)
        result = subprocess.run(['node', '-e', script], cwd=project,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'version': '1.64.1', 'browser': manifest,
                                                     'executable': '/synthetic/owned/chrome'})
        self.run_bounded.assert_not_called(); self.fixtures.create.assert_not_called()

    def test_prepare_mismatches_or_bounded_build_failure_never_mark_prepared(self):
        invalid_inputs = [
            {'system': 'Darwin'}, {'machine': 'x86_64'}, {'daemon': 'linux/amd64'},
            {'node': 'v24.19.0'}, {'pnpm': '10.28.2'}, {'checkout': 'c' * 40}, {'dirty': True},
            {'playwright': '1.65.0'}, {'revision': '9999'}, {'browserManifestVersion': '155.0.0.0'},
            {'binary': 'outside'}, {'binary': 'missing'}, {'browserVersion': 'Chromium 155.0.0.0'},
            {'browserVersion': 'Chromium 156.0.8078.40'},
            {'runnerArch': 'X64'}, {'imageArchitecture': 'amd64'}, {'imageOs': 'windows'},
            {'buildLog': 'OFFLINE MOCK rustc 1.94.0\nv22.23.4\n'},
            {'buildLog': 'OFFLINE MOCK rustc 1.93.0\nv22.23.40\n'},
            {'buildLog': 'OFFLINE MOCK no actual version markers'}, {'buildTimeout': True},
        ]
        for changes in invalid_inputs:
            with self.subTest(changes=changes), self.mocked_prepare(changes) as (work, state, *_):
                with self.assertRaises((RuntimeError, subprocess.CalledProcessError, TimeoutError)):
                    ci.prepare(work, state)
                self.assertFalse(state.get('prepared', False))
                self.run_bounded.assert_not_called()

    def test_known_secrets_are_replaced_before_publication(self):
        self.write('results.json', {'value': 'synthetic-password'})
        errors = ci.publish(self.work / 'evidence', self.output, ['synthetic-password'], self.work)
        self.assertEqual(errors, [])
        self.assertEqual(ci.read_json(self.output / 'results.json'), {'value': '[redacted]'})

    def test_ci_entry_rejects_nonprivate_roots_before_external_operations(self):
        self.work.chmod(0o755)
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_TEMP': str(self.root)}):
            with self.assertRaises(SystemExit):
                ci.main(['prepare', '--work', str(self.work), '--output', str(self.output)])
        self.command.assert_not_called()
        self.run_bounded.assert_not_called()

    def test_jwt_uri_and_private_key_are_rejected(self):
        values = ['eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.signature',
                  'postgresql://synthetic:password@localhost/db',
                  '-----BEGIN PRIVATE KEY-----']
        for value in values:
            with self.subTest(value=value):
                self.write('results.json', {'value': value})
                self.assertTrue(ci.publish(self.work / 'evidence', self.output))
                self.assertFalse((self.output / 'results.json').exists())

    def test_unknown_files_and_symlinks_are_rejected(self):
        (self.work / 'evidence/raw.env').write_text('private')
        (self.work / 'evidence/results.json').symlink_to(self.work / 'evidence/raw.env')
        errors = ci.publish(self.work / 'evidence', self.output)
        self.assertEqual({item['error'] for item in errors}, {'NotWhitelisted', 'SymlinkRejected'})
        self.assertEqual(list(self.output.iterdir()), [])

    def test_only_allowed_decoded_files_are_published(self):
        self.write('clients/ui-c-results.json', {'complete': True})
        self.assertEqual(ci.publish(self.work / 'evidence', self.output), [])
        self.assertTrue((self.output / 'clients/ui-c-results.json').is_file())

    def test_runtime_coverage_exact_mapping(self):
        for suite in ['gates', 'n2_mac']:
            with self.subTest(suite=suite):
                definition = self.write_runtime_results(suite)
                ci.validate_coverage(suite, self.output)
                result = ci.read_json(self.output / 'functional-coverage.json')
                self.assertEqual(result['missing'], [])
                self.assertEqual(len(result['executed']), len(definition['cases']))

    def test_runtime_unknown_duplicate_missing_or_incomplete_rejected(self):
        for suite in ['gates', 'n2_mac']:
            for mutation in ['unknown', 'duplicate', 'missing', 'incomplete', 'cleanup']:
                with self.subTest(suite=suite, mutation=mutation):
                    definition = self.write_runtime_results(suite)
                    filename = definition['resultFiles'][0]
                    result = ci.read_json(self.output / filename)
                    if mutation == 'unknown': result['cases'][0] = 'unexpected case'
                    if mutation == 'duplicate': result['cases'].append(result['cases'][0])
                    if mutation == 'missing': result['cases'].pop()
                    if mutation == 'incomplete': result['complete'] = False
                    if mutation == 'cleanup': result['cleanupErrors'] = [{'error': 'offline injected'}]
                    ci.write_json(self.output / filename, result)
                    with self.assertRaises(ValueError): ci.validate_coverage(suite, self.output)

    def test_all_six_functional_suites_exact_mapping(self):
        suites = [s for s in ci.SUITES if s not in ['gates', 'n2_mac']]
        self.assertEqual(len(suites), 6)
        for suite in suites:
            with self.subTest(suite=suite):
                self.write_functional_results(suite)
                ci.validate_coverage(suite, self.output)

    def test_six_suite_unknown_duplicate_missing_and_wrong_mode_rejected(self):
        for suite in [s for s in ci.SUITES if s not in ['gates', 'n2_mac']]:
            for mutation in ['unknown', 'duplicate', 'missing', 'wrong-profile', 'failed']:
                with self.subTest(suite=suite, mutation=mutation):
                    result = self.functional_result(suite)
                    if mutation == 'unknown': result['executed'][0]['id'] = 'not-selected'
                    if mutation == 'duplicate': result['executed'].append(result['executed'][0])
                    if mutation == 'missing': result['executed'].pop()
                    if mutation == 'wrong-profile': result['profile'] = 'desktop'
                    if mutation == 'failed': result['status'] = 'failed'
                    ci.write_json(self.output / 'functional-coverage.json', result)
                    with self.assertRaises(ValueError): ci.validate_coverage(suite, self.output)

    def test_functional_result_and_excluded_metadata_cannot_false_pass(self):
        for mutation in ['result-missing', 'incomplete', 'page-errors', 'cleanup', 'failure',
                         'missing-case', 'duplicate-case', 'excluded']:
            with self.subTest(mutation=mutation):
                self.write_functional_results('clients')
                result_path = self.output / ci.RESULT_FILES['clients']
                result = ci.read_json(result_path)
                if mutation == 'incomplete': result['complete'] = False
                if mutation == 'page-errors': result['pageErrors'] = ['offline error']
                if mutation == 'cleanup': result['cleanupErrors'] = [{'error': 'Error'}]
                if mutation == 'failure': result['failure'] = {'name': 'AssertionError'}
                if mutation == 'missing-case': result['cases'].pop()
                if mutation == 'duplicate-case': result['cases'].append(result['cases'][0])
                ci.write_json(result_path, result)
                if mutation == 'result-missing': result_path.unlink()
                if mutation == 'excluded':
                    coverage = ci.read_json(self.output / 'functional-coverage.json')
                    coverage['excluded'] = []
                    ci.write_json(self.output / 'functional-coverage.json', coverage)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    ci.validate_coverage('clients', self.output)

    def test_verify_rejects_missing_or_tampered_seal_and_resealed_incomplete_suites(self):
        mutations = ['no-seal', 'hash', 'missing-file', 'extra-file', 'schema', 'sanitize', 'escape',
                     'missing-suite', 'incomplete-suite', 'bad-execution', 'bad-cleanup', 'missing-result',
                     'bad-coverage', 'missing-preparation', 'wrong-source', 'missing-runtime-log']
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                shutil.rmtree(self.output); self.output.mkdir(mode=0o700)
                self.complete_mock_publication()
                seal_path = self.output / 'publication.json'
                seal = ci.read_json(seal_path)
                if mutation == 'no-seal': seal_path.unlink()
                if mutation == 'hash': seal['files']['final-summary.json'] = '0' * 64
                if mutation == 'missing-file': (self.output / 'clients/ui-c-results.json').unlink()
                if mutation == 'extra-file': ci.write_json(self.output / 'results.json', {})
                if mutation == 'schema': seal['schemaVersion'] = True
                if mutation == 'sanitize': seal['sanitized'] = False
                if mutation == 'escape': seal['files']['../private.json'] = '0' * 64
                if mutation in ['hash', 'schema', 'sanitize', 'escape']: ci.write_json(seal_path, seal)
                if mutation in ['missing-suite', 'incomplete-suite']:
                    summary = ci.read_json(self.output / 'suite-summary.json')
                    if mutation == 'missing-suite': summary['suites'].pop()
                    else: summary['complete'] = False
                    ci.write_json(self.output / 'suite-summary.json', summary)
                if mutation in ['bad-execution', 'bad-cleanup']:
                    path = self.output / 'clients/execution.json'; record = ci.read_json(path)
                    if mutation == 'bad-execution': record['exitCode'] = 1
                    else: record['cleanup']['errors'] = [{'error': 'RuntimeError'}]
                    ci.write_json(path, record)
                if mutation == 'missing-result': (self.output / 'clients/ui-c-results.json').unlink()
                if mutation == 'bad-coverage':
                    path = self.output / 'gates/functional-coverage.json'
                    coverage = ci.read_json(path); coverage['executed'].pop(); ci.write_json(path, coverage)
                if mutation == 'missing-preparation': (self.output / 'environment.json').unlink()
                if mutation == 'wrong-source': ci.write_json(self.output / 'build/source-manifest.json', {'git_head': 'c' * 40})
                if mutation == 'missing-runtime-log': (self.output / 'gates/runtime/enabled-runtime.txt').unlink()
                if mutation in mutations[7:]: self.seal_mock_publication()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    ci.verify(self.work, self.output, self.state)

    def test_finalize_cannot_trust_state_without_complete_suite_evidence(self):
        self.allow_empty_docker_readback()
        self.assertFalse(ci.finalize(self.work, self.output, self.state))
        self.assertEqual(self.final_summary()['errors'][0]['resource'], 'suite-evidence')
        self.assertTrue((self.work / 'evidence').is_dir())

    def test_main_rejects_wrong_paths_before_creating_or_touching_them(self):
        unrelated = self.root / 'unrelated-new'
        with self.main_environment(), self.assertRaises(SystemExit):
            ci.main(['prepare', '--work', str(unrelated), '--output', str(self.output)])
        self.assertFalse(unrelated.exists())
        self.command.assert_not_called(); self.run_bounded.assert_not_called()

    def test_main_rejects_symlink_roots_and_private_control_paths_without_mutating_target(self):
        for name in ['root', 'public-ancestor', 'tmp', 'evidence', 'browsers', 'job-state.json',
                     'job-state.json.next', 'job-started-at', 'secrets.json', 'fixtures.jsonl', 'processes.jsonl']:
            with self.subTest(name=name):
                target = self.root / ('target-' + name.replace('.', '-'))
                target.mkdir(); sentinel = target / 'sentinel'; sentinel.write_text('keep')
                linked = (self.work if name == 'root' else self.root / 'n2-public' if name == 'public-ancestor'
                          else self.work / name)
                backup = linked.with_name(linked.name + '-backup')
                if linked.exists(): linked.rename(backup)
                linked.symlink_to(target, target_is_directory=True)
                try:
                    with self.main_environment(), self.assertRaises(SystemExit):
                        ci.main(['prepare', '--work', str(self.work), '--output', str(self.output)])
                    self.assertEqual(list(target.iterdir()), [sentinel])
                    self.assertEqual(sentinel.read_text(), 'keep')
                finally:
                    linked.unlink()
                    if backup.exists(): backup.rename(linked)
        self.command.assert_not_called(); self.run_bounded.assert_not_called()

    def test_job_budget_reserves_cleanup_and_rejects_invalid_clock(self):
        (self.work / 'job-started-at').write_text('1000')
        with patch.object(ci.time, 'time', return_value=1100):
            self.assertEqual(ci.remaining_job(self.work), 6020)
        with patch.object(ci.time, 'time', return_value=900):
            with self.assertRaises(ValueError): ci.remaining_job(self.work)
        with patch.object(ci.time, 'time', return_value=90000):
            with self.assertRaises(ValueError): ci.remaining_job(self.work)
        with patch.object(ci.time, 'time', return_value=8000):
            self.assertEqual(ci.remaining_job(self.work), 0)

    def test_finalize_success_requires_private_cleanup(self):
        self.allow_empty_docker_readback()
        self.complete_mock_evidence(self.work / 'evidence')
        self.assertTrue(ci.finalize(self.work, self.output, self.state))
        self.assertEqual(self.final_summary()['status'], 'passed')
        for name in ['tmp', 'evidence', 'browsers']:
            self.assertFalse((self.work / name).exists())

    def test_private_directory_failure_cannot_publish_pass(self):
        self.allow_empty_docker_readback()
        original = shutil.rmtree
        def fail_private(path, *args, **kwargs):
            if Path(path) == self.work / 'tmp': raise PermissionError('offline injected')
            return original(path, *args, **kwargs)
        with patch.object(ci.shutil, 'rmtree', side_effect=fail_private):
            self.assertFalse(ci.finalize(self.work, self.output, self.state))
        summary = self.final_summary()
        self.assertEqual(summary['status'], 'failed')
        self.assertEqual(summary['cleanup'], 'failed_or_unknown')
        self.assertFalse(self.state['finalized'])

    def test_pending_browser_profiles_preserve_fixture_dependencies(self):
        self.allow_empty_docker_readback()
        for name in ['idp-n2-chrome-offline', 'idp-n2-linux-l05-offline', 'playwright-offline']:
            with self.subTest(name=name):
                profile = self.work / 'tmp' / name
                profile.mkdir()
                (profile / 'sentinel').write_text('private profile')
                self.assertTrue(ci.pending_profiles(self.work))
                self.assertFalse(ci.finalize(self.work, self.output, self.state))
                self.assertTrue((profile / 'sentinel').exists())
                self.fixtures.load.assert_not_called()
                self.assertIn({'resource': 'browser-profile', 'error': 'ExitUnconfirmed'}, self.final_summary()['errors'])
                shutil.rmtree(profile)

    def test_run_pending_browser_profile_skips_fixture_cleanup(self):
        fixture = self.fake_fixture()
        (self.work / 'tmp/playwright-offline').mkdir()
        self.run_bounded.side_effect = None
        self.run_bounded.return_value = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(ci, 'validate_coverage'):
            self.assertFalse(ci.run_suites(self.work, self.state, ['clients']))
        fixture.cleanup.assert_not_called()
        record = ci.read_json(self.work / 'evidence/clients/execution.json')
        self.assertEqual(record['cleanup']['errors'][0]['error'], 'ExitUnconfirmed')
        self.assertTrue(fixture.directory.exists())

    def test_owned_label_readback_nonempty_or_unknown_fails(self):
        for outcome in ['remaining-owned-id', RuntimeError('offline daemon unavailable')]:
            with self.subTest(outcome=type(outcome).__name__):
                self.command.side_effect = outcome if isinstance(outcome, Exception) else None
                self.command.return_value = outcome
                self.assertFalse(ci.finalize(self.work, self.output, self.state))
                self.assertEqual(self.final_summary()['status'], 'failed')
                self.assertFalse(self.final_summary()['evidenceComplete'])
                for call in self.command.call_args_list:
                    filters = ' '.join(call.args[0])
                    self.assertIn('label=idp.n2-linux.ci.run_id=123', filters)
                    self.assertIn('label=idp.n2-linux.ci.source_sha=' + 'a' * 40, filters)

    def test_verify_requires_all_delivery_gates(self):
        self.complete_mock_publication()
        ci.verify(self.work, self.output, self.state)
        for key, value in [('IDP_N2_JOB_STATUS', 'failure'), ('IDP_N2_ARTIFACT_OUTCOME', 'failure'),
                           ('IDP_N2_ARTIFACT_ID', ''), ('IDP_N2_ARTIFACT_ID', 'not-numeric')]:
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                with self.assertRaises(RuntimeError): ci.verify(self.work, self.output, self.state)
        self.state['finalized'] = False
        with self.assertRaises(RuntimeError): ci.verify(self.work, self.output, self.state)

    def test_verify_rejects_unknown_file_and_symlink(self):
        self.complete_mock_publication()
        unknown = self.output / 'raw.env'
        unknown.write_text('not permitted')
        with self.assertRaises(ValueError): ci.verify(self.work, self.output, self.state)
        unknown.unlink()
        linked = self.output / 'results.json'
        linked.symlink_to(self.output / 'final-summary.json')
        with self.assertRaises(ValueError): ci.verify(self.work, self.output, self.state)

    def test_verify_step_summary_records_existing_action_metadata_and_pending_expiry(self):
        self.complete_mock_publication()
        step_summary = self.root / 'step-summary.md'
        metadata = {'GITHUB_STEP_SUMMARY': str(step_summary),
                    'IDP_N2_ARTIFACT_URL': 'https://github.com/example/repo/actions/runs/123/artifacts/12345',
                    'IDP_N2_ARTIFACT_DIGEST': 'b' * 64}
        with patch.dict(os.environ, metadata):
            ci.verify(self.work, self.output, self.state)
            self.assertIn('b' * 64, step_summary.read_text())
            self.assertIn('12345', step_summary.read_text())
            with patch.dict(os.environ, {'IDP_N2_ARTIFACT_URL': 'https://untrusted.example/artifact'}):
                with self.assertRaises(ValueError): ci.verify(self.work, self.output, self.state)
            with patch.dict(os.environ, {'IDP_N2_ARTIFACT_DIGEST': 'not-a-digest'}):
                with self.assertRaises(ValueError): ci.verify(self.work, self.output, self.state)

    def test_finalize_secret_pattern_failure_does_not_copy_secret(self):
        self.allow_empty_docker_readback()
        self.write('results.json', {'value': 'postgres://synthetic:password@localhost/db'})
        self.assertFalse(ci.finalize(self.work, self.output, self.state))
        self.assertFalse((self.output / 'results.json').exists())
        self.assertEqual(self.final_summary()['status'], 'failed')

    def main_environment(self):
        return patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_TEMP': str(self.root),
                                      'DOCKER_CONTEXT': 'default', 'DOCKER_HOST': 'unix:///var/run/docker.sock'})

    def test_main_prepare_failure_records_class_without_exception_secret(self):
        with self.main_environment(), patch.object(ci, 'prepare', side_effect=RuntimeError('synthetic-private-error')):
            status = ci.main(['prepare', '--work', str(self.work), '--output', str(self.output)])
        self.assertEqual(status, 1)
        failure = ci.read_json(self.work / 'evidence/failure.json')
        self.assertEqual({key: failure[key] for key in ['phase', 'status', 'error']},
                         {'phase': 'prepare', 'status': 'failed', 'error': 'RuntimeError'})
        self.assertIsNone(failure['stage'])  # The injected error precedes all preflight steps.
        state = ci.read_json(self.work / 'job-state.json')
        self.assertEqual(state['failedPhase'], 'prepare')
        self.assertNotIn('synthetic-private-error', json.dumps(failure))

    def test_main_finalize_exception_leaves_safe_public_failure_summary(self):
        with self.main_environment(), patch.object(ci, 'finalize', side_effect=PermissionError('synthetic-private-error')):
            status = ci.main(['finalize', '--work', str(self.work), '--output', str(self.output)])
        self.assertEqual(status, 1)
        summary = self.final_summary()
        self.assertEqual(summary['status'], 'failed')
        self.assertFalse(summary['evidenceComplete'])
        self.assertNotIn('synthetic-private-error', json.dumps(summary))

    def test_run_prepare_checker_and_cleanup_failures_are_recorded(self):
        for failure in ['prepare', 'checker', 'cleanup']:
            with self.subTest(failure=failure):
                directory = self.work / 'evidence/clients'
                if directory.exists(): shutil.rmtree(directory)
                fixture_directory = self.work / 'tmp/idp-ui-b-offline'
                if fixture_directory.exists(): shutil.rmtree(fixture_directory)
                fixture = self.fake_fixture()
                if failure == 'prepare': fixture.prepare.side_effect = RuntimeError('offline preparation')
                if failure == 'cleanup': fixture.cleanup.return_value['errors'] = [{'error': 'offline cleanup'}]
                self.run_bounded.side_effect = None
                self.run_bounded.return_value = subprocess.CompletedProcess([], 3 if failure == 'checker' else 0, '', '')
                with patch.object(ci, 'validate_coverage'):
                    self.assertFalse(ci.run_suites(self.work, self.state, ['clients']))
                record = ci.read_json(directory / 'execution.json')
                summary = ci.read_json(self.work / 'evidence/suite-summary.json')
                self.assertEqual(record['status'], 'failed')
                self.assertEqual(record['exitCode'], 1)
                self.assertFalse(summary['complete'])
                self.assertFalse(self.state['suitesComplete'])

    def test_create_failure_is_recorded_without_cleanup_guess(self):
        self.fixtures.create.side_effect = RuntimeError('offline create failure')
        self.assertFalse(ci.run_suites(self.work, self.state, ['clients']))
        record = ci.read_json(self.work / 'evidence/clients/execution.json')
        self.assertEqual(record['status'], 'failed')
        self.fixtures.load.assert_not_called()

    def test_timeout_stops_remaining_suites(self):
        self.fake_fixture()
        self.run_bounded.side_effect = subprocess.TimeoutExpired('offline', 1)
        self.assertFalse(ci.run_suites(self.work, self.state, ['clients', 'authorization']))
        self.fixtures.create.assert_called_once()
        self.assertFalse((self.work / 'evidence/authorization').exists())

    def test_budget_exhaustion_writes_explicit_not_executed_summary(self):
        with patch.object(ci, 'remaining_job', return_value=479):
            self.assertFalse(ci.run_suites(self.work, self.state, ['clients', 'authorization']))
        self.fixtures.create.assert_not_called()
        summary = ci.read_json(self.work / 'evidence/suite-summary.json')
        self.assertFalse(summary['complete'])
        self.assertEqual(summary['suites'][0]['status'], 'not_executed')

    def test_workflow_runner_paths_are_scoped_to_initialization_step(self):
        workflow = (ci.ROOT / '.github/workflows/n2-functional.yml').read_text()
        job_environment = workflow.split('    env:\n', 1)[1].split('    steps:\n', 1)[0]
        self.assertNotRegex(job_environment, r'\$\{\{\s*runner\.',
                            'GitHub rejects runner context in job-level env')
        initialization = workflow.split('      - name: Initialize private work and public evidence roots\n', 1)[1]
        initialization = initialization.split('\n      - name: Checkout reviewed ref', 1)[0]
        step_environment = initialization.split('        env:\n', 1)[1].split('        run: |\n', 1)[0]
        names = set(re.findall(r'^          ([A-Z0-9_]+):', step_environment, re.M))
        self.assertEqual(names, {'N2_WORK', 'N2_PUBLIC', 'TMPDIR', 'PLAYWRIGHT_BROWSERS_PATH'})
        self.assertEqual(step_environment.count('${{ runner.temp }}'), 4)

    def test_workflow_initialization_exports_only_validated_owned_paths(self):
        workflow = (ci.ROOT / '.github/workflows/n2-functional.yml').read_text()
        section = workflow.split('      - name: Initialize private work and public evidence roots\n', 1)[1]
        script = textwrap.dedent(section.split('        run: |\n', 1)[1].split('\n      - name: Checkout reviewed ref', 1)[0])
        for mutation in ['valid', 'wrong-work', 'symlink']:
            with self.subTest(mutation=mutation):
                base = (self.root / ('export-' + mutation)).resolve(); base.mkdir()
                work = base / 'idp-n2-ci-123-1'; public = base / 'n2-public/123/1'
                target = base / 'target'; target.mkdir()
                sentinel = target / 'sentinel'; sentinel.write_text('keep')
                export = base / 'github-env'; export.write_text('PREEXISTING=kept\n')
                if mutation == 'symlink': work.symlink_to(target, target_is_directory=True)
                expected = {'N2_WORK': str(work), 'N2_PUBLIC': str(public),
                            'TMPDIR': str(work / 'tmp'), 'PLAYWRIGHT_BROWSERS_PATH': str(work / 'browsers')}
                environment = {**os.environ, **expected, 'RUNNER_TEMP': str(base), 'GITHUB_ENV': str(export)}
                if mutation == 'wrong-work': environment['N2_WORK'] = str(base / 'wrong')
                result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                                        cwd=base, env=environment, capture_output=True, text=True, timeout=5)
                if mutation == 'valid':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    lines = export.read_text().splitlines()
                    self.assertEqual(lines[0], 'PREEXISTING=kept')
                    self.assertEqual(len(lines), 5)
                    self.assertEqual(dict(line.split('=', 1) for line in lines[1:]), expected)
                    self.assertTrue((work / 'tmp').is_dir())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(export.read_text(), 'PREEXISTING=kept\n')
                    self.assertFalse(public.exists())
                self.assertEqual(sentinel.read_text(), 'keep')
                self.assertFalse((target / 'tmp').exists())
        self.command.assert_not_called(); self.run_bounded.assert_not_called()

    def test_workflow_initialization_validates_identity_and_paths_before_writing(self):
        workflow = (ci.ROOT / '.github/workflows/n2-functional.yml').read_text()
        section = workflow.split('      - name: Initialize private work and public evidence roots\n', 1)[1]
        script = textwrap.dedent(section.split('        run: |\n', 1)[1].split('\n      - name: Checkout reviewed ref', 1)[0])
        for mutation in ['valid', 'wrong-work', 'root-symlink', 'start-symlink']:
            with self.subTest(mutation=mutation):
                base = (self.root / ('initialize-' + mutation)).resolve(); base.mkdir()
                work = base / 'idp-n2-ci-123-1'; public = base / 'n2-public/123/1'
                target = base / 'target'; target.mkdir()
                sentinel = target / 'sentinel'; sentinel.write_text('keep')
                if mutation == 'root-symlink': work.symlink_to(target, target_is_directory=True)
                if mutation == 'start-symlink':
                    work.mkdir(mode=0o700); (work / 'job-started-at').symlink_to(sentinel)
                environment = {**os.environ, 'RUNNER_TEMP': str(base), 'N2_PUBLIC': str(public),
                               'N2_WORK': str(base / 'wrong' if mutation == 'wrong-work' else work)}
                result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                                        cwd=base, env=environment, capture_output=True, text=True, timeout=5)
                if mutation == 'valid':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertGreater(float((work / 'job-started-at').read_text()), 0)
                    self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(public.exists())
                    self.assertFalse((target / 'tmp').exists())
                self.assertEqual(sentinel.read_text(), 'keep')

    def test_workflow_finalize_failure_fallback_is_safe_and_preserves_status(self):
        workflow = (ci.ROOT / '.github/workflows/n2-functional.yml').read_text()
        section = workflow.split('      - name: Finalize cleanup and sanitized evidence\n', 1)[1]
        script = textwrap.dedent(section.split('        run: |\n', 1)[1].split('\n      - name: Upload public evidence whitelist', 1)[0])
        for name, source, expected in [('missing', None, 1), ('nonzero', 'raise SystemExit(7)', 7),
                                       ('import-error', 'import nonexistent_n2_fixture_module', 1)]:
            with self.subTest(name=name):
                base = (self.root / name).resolve()
                (base / 'scripts').mkdir(parents=True)
                if source: (base / 'scripts/run_management_n2_ci.py').write_text(source)
                public = base / 'n2-public/123/1'
                public.mkdir(parents=True)
                (public / 'untrusted.log').write_text('must not upload')
                outputs = base / 'outputs'; outputs.write_text('')
                environment = {**os.environ, 'RUNNER_TEMP': str(base), 'N2_PUBLIC': str(public),
                               'N2_WORK': str(base / 'private'), 'GITHUB_OUTPUT': str(outputs)}
                result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                                        cwd=base, env=environment, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual([p.name for p in public.iterdir()], ['bootstrap-failure.json'])
                self.assertEqual(ci.read_json(public / 'bootstrap-failure.json')['status'], 'failed')
                self.assertEqual(outputs.read_text(), f'public-path={public}\n')

    def test_workflow_finalize_symlink_fails_without_upload_path(self):
        workflow = (ci.ROOT / '.github/workflows/n2-functional.yml').read_text()
        section = workflow.split('      - name: Finalize cleanup and sanitized evidence\n', 1)[1]
        script = textwrap.dedent(section.split('        run: |\n', 1)[1].split('\n      - name: Upload public evidence whitelist', 1)[0])
        base = (self.root / 'symlink-fallback').resolve(); base.mkdir()
        target = base / 'target'; target.mkdir()
        (target / 'sentinel').write_text('preserve')
        (base / 'n2-public').symlink_to(target, target_is_directory=True)
        outputs = base / 'outputs'; outputs.write_text('')
        environment = {**os.environ, 'RUNNER_TEMP': str(base), 'N2_PUBLIC': str(base / 'n2-public/123/1'),
                       'N2_WORK': str(base / 'private'), 'GITHUB_OUTPUT': str(outputs)}
        result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                                cwd=base, env=environment, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outputs.read_text(), '')
        self.assertEqual((target / 'sentinel').read_text(), 'preserve')

    def test_workflow_nonzero_finalizer_preserves_only_complete_sealed_failure_evidence(self):
        workflow = (ci.ROOT / '.github/workflows/n2-functional.yml').read_text()
        section = workflow.split('      - name: Finalize cleanup and sanitized evidence\n', 1)[1]
        script = textwrap.dedent(section.split('        run: |\n', 1)[1].split('\n      - name: Upload public evidence whitelist', 1)[0])
        for mutation in ['valid', 'hash-mismatch', 'extra-file', 'symlink', 'missing-file',
                         'wrong-schema', 'not-sanitized', 'relative-escape', 'non-object', 'passed-summary']:
            with self.subTest(mutation=mutation):
                base = (self.root / ('publication-' + mutation)).resolve()
                (base / 'scripts').mkdir(parents=True)
                (base / 'scripts/run_management_n2_ci.py').write_text('raise SystemExit(7)')
                public = base / 'n2-public/123/1'
                (public / 'clients').mkdir(parents=True)
                ci.write_json(public / 'final-summary.json', {'status': 'failed', 'evidenceComplete': False})
                if mutation == 'passed-summary':
                    ci.write_json(public / 'final-summary.json', {'status': 'passed'})
                ci.write_json(public / 'clients/failure.json', {'case': 'offline synthetic diagnostic', 'status': 'failed'})
                files = {path.relative_to(public).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in public.rglob('*') if path.is_file()}
                manifest = {'schemaVersion': 1, 'sanitized': True, 'files': files}
                outside = base / 'outside-private'; outside.write_text('private sentinel must remain')
                if mutation == 'hash-mismatch': files['clients/failure.json'] = '0' * 64
                if mutation == 'extra-file': (public / 'untrusted.env').write_text('must not upload')
                if mutation == 'symlink': (public / 'linked-secret').symlink_to(outside)
                if mutation == 'missing-file': (public / 'clients/failure.json').unlink()
                if mutation == 'wrong-schema': manifest['schemaVersion'] = 2
                if mutation == 'not-sanitized': manifest['sanitized'] = False
                if mutation == 'relative-escape': files['../outside-private'] = hashlib.sha256(outside.read_bytes()).hexdigest()
                if mutation == 'non-object': manifest = []
                ci.write_json(public / 'publication.json', manifest)
                outputs = base / 'outputs'; outputs.write_text('')
                environment = {**os.environ, 'RUNNER_TEMP': str(base), 'N2_PUBLIC': str(public),
                               'N2_WORK': str(base / 'private'), 'GITHUB_OUTPUT': str(outputs)}
                result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                                        cwd=base, env=environment, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 7, result.stderr)
                self.assertEqual(outputs.read_text(), f'public-path={public}\n')
                self.assertEqual(outside.read_text(), 'private sentinel must remain')
                if mutation == 'valid':
                    self.assertEqual({path.relative_to(public).as_posix() for path in public.rglob('*') if path.is_file()},
                                     {'publication.json', 'final-summary.json', 'clients/failure.json'})
                    self.assertEqual(ci.read_json(public / 'clients/failure.json')['case'], 'offline synthetic diagnostic')
                    self.assertEqual(ci.read_json(public / 'final-summary.json')['status'], 'failed')
                else:
                    self.assertEqual([path.name for path in public.iterdir()], ['bootstrap-failure.json'])
                    self.assertEqual(ci.read_json(public / 'bootstrap-failure.json')['status'], 'failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
