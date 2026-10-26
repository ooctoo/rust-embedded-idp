"""Offline gates for incomplete results and fixture preparation interruption."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import run_ci_e2e as runner


class RunnerTests(unittest.TestCase):
    def report(self):
        return {'groups': [{'id': f'E0{i}', 'status': 'passed'} for i in range(1, 7)],
                'status': 'passed', 'complete': True, 'browser_closed': True,
                'page_error_count': 0, 'cleanup_errors': []}

    def test_complete_report(self):
        runner.validate_report(self.report())

    def test_missing_duplicate_failed_unclosed_and_page_errors_fail(self):
        mutations = [lambda r: r['groups'].pop(),
                     lambda r: r['groups'].__setitem__(5, r['groups'][0]),
                     lambda r: r['groups'][0].update(status='not_run'),
                     lambda r: r.update(complete=False),
                     lambda r: r.update(browser_closed=False),
                     lambda r: r.update(page_error_count=1),
                     lambda r: r.update(cleanup_errors=['context_close'])]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = self.report()
                mutate(report)
                with self.assertRaises(RuntimeError):
                    runner.validate_report(report)

    @patch.object(runner, 'stop_process_group')
    @patch.object(runner.subprocess, 'Popen')
    def test_prepare_timeout_stops_owned_process(self, popen, stop):
        process = popen.return_value
        process.communicate.side_effect = subprocess.TimeoutExpired('fixture', 300)
        with self.assertRaises(subprocess.TimeoutExpired):
            runner.prepare(['fixture'], {})
        stop.assert_called_once_with(process)

    @patch.object(runner, 'stop_process_group')
    @patch.object(runner.subprocess, 'Popen')
    def test_prepare_cancellation_is_not_retryable_eintr(self, popen, stop):
        process = popen.return_value
        process.communicate.side_effect = runner.RunInterrupted()
        self.assertFalse(issubclass(runner.RunInterrupted, OSError))
        with self.assertRaises(runner.RunInterrupted):
            runner.prepare(['fixture'], {})
        stop.assert_called_once_with(process)

    @patch.object(runner.subprocess, 'Popen')
    def test_prepare_failure_does_not_expose_private_output(self, popen):
        popen.return_value.communicate.return_value = ('password', 'secret-token')
        popen.return_value.returncode = 1
        with self.assertRaisesRegex(RuntimeError, '^fixture preparation failed$'):
            runner.prepare(['fixture'], {})

    def test_unconfirmed_browser_exit_retains_owned_recovery_data(self):
        with tempfile.TemporaryDirectory() as temp:
            private = Path(temp) / 'private'
            private.mkdir()
            module = Path(temp) / 'playwright.mjs'
            module.touch()
            output = Path(temp) / 'public'
            fixture = private / 'idp-ui-b-fake' / 'state.json'
            fixture.parent.mkdir()
            fixture.write_text('{}')
            with patch('sys.argv', ['runner', '--image', 'fixture', '--playwright', str(module),
                                    '--output', str(output)]), \
                    patch.object(runner.tempfile, 'mkdtemp', return_value=str(private)), \
                    patch.object(runner.subprocess, 'check_output', return_value='fixture'), \
                    patch.object(runner, 'prepare', return_value={'fixture_file': str(fixture), 'postgres_version': '18'}), \
                    patch.object(runner, 'run_bounded', side_effect=RuntimeError('owned exit unknown')) as command:
                self.assertEqual(runner.main(), 1)
            result = json.loads((output / 'execution.json').read_text())
            self.assertEqual(result['cleanup'], 'failed')
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(fixture.exists())
            self.assertEqual(command.call_count, 1)

    def test_missing_module_writes_failed_summary_and_cleans(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'public'
            with patch('sys.argv', ['runner', '--image', 'unused', '--playwright',
                                    str(Path(temp) / 'missing'), '--output', str(output)]):
                self.assertEqual(runner.main(), 1)
            result = json.loads((output / 'execution.json').read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['cleanup'], 'passed')
            self.assertEqual(result['cases'], 'not_completed')


if __name__ == '__main__':
    unittest.main()
