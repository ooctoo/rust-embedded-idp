"""Run independent Linux-container fixtures with the installed Mac Chrome."""
import argparse
import datetime
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from prepare_management_n2_linux import Fixture

ROOT = Path(__file__).resolve().parent.parent


def redact(value, state):
    for key in ['password', 'db_password', 'db_uri']:
        if state.get(key): value = value.replace(state[key], '[redacted]')
    for path, replacement in [(str(ROOT), '<repo>'), (str(Path.home()), '<home>'),
                               (state['dir'], '<fixture>'), (str(Path(tempfile.gettempdir()).resolve()), '<tmp>')]:
        value = value.replace(path, replacement)
    return re.sub(r'data:text/javascript;base64,[A-Za-z0-9+/=]+', 'data:text/javascript;base64,[source omitted]', value)


def profile_recovery_required(output, directory):
    if (directory / 'l05-private-profile-recovery.txt').exists():
        return True
    for name in ['results.json', 'l05-restart-results.json']:
        path = output / name
        if path.exists():
            try:
                if json.loads(path.read_text()).get('cleanupErrors'):
                    return True
            except (ValueError, OSError):
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', required=True); parser.add_argument('--prepare', required=True)
    parser.add_argument('--postgres', required=True); parser.add_argument('--playwright', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--suites', nargs='+', required=True, choices=['gates', 'n2_mac', 'navigation', 'clients', 'authorization', 'security', 'n1', 'console'])
    parser.add_argument('--profile', choices=['mac-chrome', 'ci-functional'], default='mac-chrome')
    parser.add_argument('--ci-work', type=Path, help='owned private root prepared by run_management_n2_ci.py')
    args = parser.parse_args()
    if args.profile == 'ci-functional':
        from run_management_n2_ci import BASES, SUITES, main as ci_main, read_json
        if args.ci_work is None or args.suites != SUITES:
            parser.error('CI profile requires its prepared work root and all eight suites in order')
        state = read_json(args.ci_work / 'job-state.json')
        if (args.runtime != state.get('runtime') or args.prepare != state.get('prepare') or
                args.postgres != BASES['postgres'] or str(args.playwright) != state.get('playwright')):
            parser.error('CI inputs differ from the prepared job state')
        return ci_main(['run', '--work', str(args.ci_work), '--output', str(args.output)])
    chrome = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
    if not chrome.is_file() or not args.playwright.is_file(): parser.error('Installed Chrome and Playwright required')
    args.output.mkdir(exist_ok=False)
    sources = [*ROOT.joinpath('scripts').glob('*management*n2*'),
               *ROOT.joinpath('scripts').glob('check_management_*.mjs'),
               ROOT / 'scripts/n2-linux/Dockerfile', ROOT / 'scripts/n2-linux/Dockerfile.dockerignore']
    (args.output / 'tool-manifest.json').write_text(json.dumps({
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sources if p.is_file()}, indent=2) + '\n')
    failed = False
    for suite in args.suites:
        output = args.output / suite; output.mkdir()
        record = {'suite': suite, 'startedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'platform': 'linux/arm64', 'headed': True, 'freshFixture': True, 'n2Layout': True}
        fixture = None; started = time.monotonic()
        try:
            fixture = Fixture.create(args.runtime, args.prepare, args.postgres)
            fixture.prepare()
            record['postgresVersion'] = fixture.state['pg_version']
            env = {**os.environ, 'IDP_UI_TEST_FIXTURE': str(fixture.directory / 'state.json'),
                   'IDP_UI_PLAYWRIGHT_PATH': str(args.playwright.resolve()), 'IDP_UI_HEADED': '1',
                   'IDP_UI_BROWSER_EXECUTABLE': str(chrome), 'IDP_UI_OUTPUT_DIR': str(output.resolve()), 'IDP_UI_N2_LAYOUT': '1'}
            commands = [['python3', '-B', 'scripts/check_management_n2_linux.py', '--fixture', env['IDP_UI_TEST_FIXTURE'], '--output', str(output / 'runtime')],
                        ['node', 'scripts/check_management_n2_linux_restart.mjs']] if suite == 'gates' else [['node', 'scripts/check_management_' + suite + '.mjs']]
            record['commands'] = []
            for command in commands:
                result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=1800)
                # Keep raw recovery paths only inside the owner-only fixture.
                # These files are deleted after successful cleanup, never published.
                (fixture.directory / (suite + '-stdout.txt')).write_text(result.stdout)
                (fixture.directory / (suite + '-stderr.txt')).write_text(result.stderr)
                record['commands'].append({'tool': Path(command[2] if command[1] == '-B' else command[1]).name,
                    'exitCode': result.returncode, 'passLines': [line for line in result.stdout.splitlines() if line.startswith('PASS ')],
                    'diagnostic': redact(result.stderr, fixture.state)})
                if result.returncode:
                    raise RuntimeError('Acceptance command failed')
            record['exitCode'] = 0
        except BaseException as error:
            failed = True; record['exitCode'] = 1
            record['error'] = {'type': type(error).__name__, 'message': redact(str(error), fixture.state) if fixture else 'Fixture unavailable'}
            if fixture:
                # Preserve only sanitized terminal diagnostics, never raw inspect/log/env.
                from prepare_management_n2_linux import docker
                logs = []
                for resource in fixture.state['resources']:
                    if resource['kind'] == 'container':
                        result = docker('logs', resource['name'], check=False)
                        logs.append({'container': resource['name'], 'diagnostic': redact(result.stdout + result.stderr, fixture.state)})
                (output / 'failure-diagnostics.json').write_text(json.dumps(logs, indent=2) + '\n')
        finally:
            if fixture:
                # Restart is performed in a child process; reload its new IDs.
                fixture = Fixture.load(fixture.directory / 'state.json')
                record['restartAttempts'] = fixture.state.get('restartAttempts', [])
                retained_profile = profile_recovery_required(output, fixture.directory)
                record['cleanup'] = fixture.cleanup(preserve_private=retained_profile)
                if retained_profile:
                    record['cleanup']['errors'].append({'resource': 'chrome-profile', 'error': 'PrivateRecoveryRequired'})
                if record['cleanup']['errors']:
                    failed = True
                    record['exitCode'] = 1
            record['durationSeconds'] = round(time.monotonic() - started, 2)
            (output / 'execution.json').write_text(json.dumps(record, indent=2) + '\n')
            print(json.dumps({'suite': suite, 'exitCode': record['exitCode'], 'cleanupErrors': record.get('cleanup', {}).get('errors'), 'durationSeconds': record['durationSeconds']}), flush=True)
    return 1 if failed else 0


if __name__ == '__main__': raise SystemExit(main())
