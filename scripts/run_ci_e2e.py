"""Run critical E2E with an owned disposable PG/reference-host fixture."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time

from n2_ci_runtime import run_bounded, stop_process_group

ROOT = Path(__file__).resolve().parent.parent


class RunInterrupted(Exception):
    """Do not let subprocess treat cancellation as a retryable EINTR."""


def prepare(command, env):
    process = subprocess.Popen(command, cwd=ROOT, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=300)
    except BaseException:
        stop_process_group(process)
        raise
    if process.returncode:
        raise RuntimeError('fixture preparation failed')
    return json.loads(stdout)


def validate_report(report):
    groups = report.get('groups', [])
    if ([group.get('id') for group in groups] != ['E01', 'E02', 'E03', 'E04', 'E05', 'E06']
            or any(group.get('status') != 'passed' for group in groups)
            or report.get('status') != 'passed' or report.get('complete') is not True
            or report.get('browser_closed') is not True
            or report.get('page_error_count') != 0 or report.get('cleanup_errors') != []):
        raise RuntimeError('missing, failed or unclean critical E2E groups')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='explicit installed PostgreSQL 18 image')
    parser.add_argument('--playwright', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='new public result directory')
    args = parser.parse_args()
    os.umask(0o077)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    private = Path(tempfile.mkdtemp(prefix='idp-ci-e2e-')).resolve()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('EMBEDDED_IDP_', 'IDP_UI_', 'IDP_N2_'))}
    env['TMPDIR'] = str(private)
    result = {'suite': 'critical-e2e', 'status': 'failed', 'cleanup': 'unknown',
              'architecture': platform.machine(), 'system': platform.system(),
              'sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'workingTreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'cases': 'not_completed'}
    def interrupted(signum, frame):
        raise RunInterrupted('E2E interrupted')
    checker_stopped = True
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        if not args.playwright.resolve().is_file():
            raise ValueError('missing Playwright module')
        result['toolVersions'] = {name: subprocess.check_output(command, text=True, timeout=10).strip()
                                  for name, command in [('node', ['node', '--version']),
                                                        ('pnpm', ['pnpm', '--version']),
                                                        ('rust', ['rustc', '--version'])]}
        result['postgresImageId'] = subprocess.check_output(
            ['docker', 'image', 'inspect', '--format={{.Id}}', args.image], text=True, timeout=15).strip()
        info = prepare(['python3', '-B', 'scripts/prepare_management_navigation.py',
                        '--image', args.image, '--isolated-cookies'], env)
        fixture = Path(info['fixture_file']).resolve()
        if fixture.parent.parent != private or fixture.name != 'state.json':
            raise ValueError('unexpected fixture location')
        result['postgresVersion'] = info['postgres_version']
        checker_stopped = False
        try:
            run = run_bounded(['node', 'scripts/check_ci_e2e.mjs'], cwd=ROOT,
                              env={**env, 'IDP_UI_TEST_FIXTURE': str(fixture),
                                   'IDP_UI_PLAYWRIGHT_PATH': str(args.playwright.resolve()),
                                   'IDP_UI_OUTPUT_DIR': str(args.output)}, timeout=600)
        except (subprocess.TimeoutExpired, RunInterrupted):
            # run_bounded propagates these only after confirming owned exit.
            checker_stopped = True
            raise
        checker_stopped = True
        result['checkerExitCode'] = run.returncode
        # No raw stdout/stderr, profiles or fixture material enters public evidence.
        report = json.loads((args.output / 'ci-e2e-results.json').read_text())
        result['cases'] = 'completed' if run.returncode == 0 else 'failed'
        validate_report(report)
        if run.returncode != 0 or report.get('status') != 'passed':
            raise RuntimeError('critical E2E failed; see case report')
        result['status'] = 'passed'
    except BaseException as error:
        result['failureType'] = type(error).__name__
        result['status'] = 'failed'
    finally:
        # A second signal must not bypass the bounded cleanup already in progress.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if not checker_stopped:
                raise RuntimeError('owned browser process exit is unconfirmed')
            for directory in private.iterdir():
                if directory.is_dir() and directory.name.startswith('idp-ui-b-'):
                    state = directory / 'state.json'
                    if not state.is_file():
                        raise RuntimeError('fixture ownership journal missing')
                    run_bounded(['python3', '-B', 'scripts/prepare_management_navigation.py',
                                 '--cleanup', str(state)], cwd=ROOT, env=env,
                                timeout=90, check=True)
            shutil.rmtree(private)
            result['cleanup'] = 'passed'
        except BaseException as error:
            result['cleanup'] = 'failed'
            result['cleanupFailureType'] = type(error).__name__
            result['status'] = 'failed'
            print('Private recovery directory retained: ' + str(private))
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        result['durationSeconds'] = round(time.monotonic() - started, 2)
        (args.output / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
