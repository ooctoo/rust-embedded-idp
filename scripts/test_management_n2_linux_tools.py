"""Offline safety tests for prepare_management_n2_linux.py.

All fixture paths are created under TemporaryDirectory and Docker is mocked.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import prepare_management_n2_linux as n2
import run_management_n2_linux as runner
from run_management_n2_linux import profile_recovery_required


class FixtureSafetyTests(unittest.TestCase):
    @patch.object(n2, 'docker')
    def test_sql_refuses_missing_container_and_uses_verified_id(self, docker):
        self.state['resources'] = [{'kind': 'container', 'name': 'postgres'}]
        with patch.object(self.fixture, 'inspect_owned', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'container is missing'):
                self.fixture.sql('select 1')
        docker.assert_not_called()
        docker.return_value = subprocess.CompletedProcess([], 0, '1\n', '')
        with patch.object(self.fixture, 'inspect_owned', return_value=self.owned_container('postgres', 'verified-pg-id')):
            self.assertEqual(self.fixture.sql('select 1'), '1')
        self.assertEqual(docker.call_args.args[:3], ('exec', '-i', 'verified-pg-id'))

    def test_private_directory_delete_failure_is_recorded_and_runner_writes_result(self):
        self.state['pg_version'] = '18.6'
        self.fixture.save()
        output = Path(self.temp.name) / 'runner-output'
        playwright = Path(self.temp.name) / 'playwright.mjs'; playwright.touch()
        original_is_file = Path.is_file
        def installed_file(path):
            return str(path).startswith('/Applications/Google Chrome.app/') or original_is_file(path)
        argv = ['runner', '--runtime', 'runtime', '--prepare', 'prepare', '--postgres', 'postgres',
                '--playwright', str(playwright), '--output', str(output), '--suites', 'navigation']
        with patch('sys.argv', argv), patch.object(Path, 'is_file', installed_file), \
             patch.object(runner.Fixture, 'create', return_value=self.fixture), \
             patch.object(runner.Fixture, 'load', return_value=self.fixture), \
             patch.object(self.fixture, 'prepare'), \
             patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'PASS mocked acceptance\n', '')), \
             patch.object(n2.shutil, 'rmtree', side_effect=PermissionError('denied')), \
             patch('builtins.print'):
            self.assertEqual(runner.main(), 1)
        record = json.loads((output / 'navigation/execution.json').read_text())
        self.assertEqual(record['exitCode'], 1)
        self.assertEqual(record['cleanup']['errors'], [{'resource': 'private-directory', 'error': 'PermissionError'}])
        self.assertFalse(record['cleanup']['privateDirectoryRemoved'])
        self.assertTrue((self.directory / 'state.json').exists())

    def test_recovery_state_is_atomic_and_owner_only_under_normal_umask(self):
        previous = os.umask(0o022)
        try:
            self.fixture.save()
        finally:
            os.umask(previous)
        path = self.directory / 'state.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text())['nonce'], self.state['nonce'])
        self.assertFalse((self.directory / 'state.next').exists())

    def test_forced_app_stop_is_not_reported_as_clean_success(self):
        self.state['resources'] = [{'kind': 'container', 'name': 'app-a'},
                                   {'kind': 'container', 'name': self.state['container']},
                                   {'kind': 'volume', 'name': 'test-data'}]
        with patch.object(self.fixture, 'remove_container', return_value={'name': 'app-a', 'exitCode': 137, 'oomKilled': False}) as remove:
            result = self.fixture.cleanup()
        self.assertEqual(remove.call_count, 1)
        self.assertEqual(result['errors'][0]['error'], 'UnexpectedForcedStop')
        self.assertFalse(result['privateDirectoryRemoved'])

    def test_profile_cleanup_errors_keep_private_recovery_diagnostics(self):
        output = self.directory / 'public-output'; output.mkdir()
        self.assertFalse(profile_recovery_required(output, self.directory))
        result = output / 'results.json'
        result.write_text(json.dumps({'cleanupErrors': [{'index': 0, 'error': 'Error'}]}))
        self.assertTrue(profile_recovery_required(output, self.directory))
        result.write_text(json.dumps({'cleanupErrors': []}))
        self.assertFalse(profile_recovery_required(output, self.directory))
        result.write_text('{partial')
        self.assertTrue(profile_recovery_required(output, self.directory))

    @patch.object(n2, 'docker')
    def test_existing_foreign_volume_is_rejected_before_use(self, docker):
        docker.side_effect = [subprocess.CompletedProcess([], 0, 'foreign-volume\n', ''),
                              subprocess.CompletedProcess([], 0, json.dumps([{'Name': 'foreign-volume', 'Labels': {}}]), '')]
        with self.assertRaisesRegex(ValueError, 'ownership mismatch'):
            self.fixture.add('volume', 'foreign-volume', ['volume', 'create', 'foreign-volume'])
        self.assertEqual(len(docker.call_args_list), 2)
        self.assertTrue((self.directory / 'state.json').exists())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='n2-tools-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'idp-ui-b-test'
        self.directory.mkdir()
        self.state = {
            'dir': str(self.directory), 'nonce': 'a' * 12, 'resources': [],
            'hosts': {}, 'prepare': 'prepare-image',
            'container': 'postgres', 'network': 'test-network',
            'data_volume': 'test-data', 'secrets_volume': 'test-secrets',
        }
        self.fixture = n2.Fixture(self.state)

    def owned_container(self, name, container_id='container-id'):
        return {
            'Id': container_id,
            'Config': {'Labels': {
                n2.OWNER: str(self.directory), 'idp.n2-linux.run': self.state['nonce'],
            }},
            'State': {'Running': False, 'ExitCode': 0},
        }

    @patch.object(n2, 'docker')
    def test_failed_inspect_and_failed_listing_propagate_daemon_error(self, docker):
        docker.side_effect = [
            subprocess.CompletedProcess([], 1, '', ''),
            RuntimeError('Docker operation failed: container'),
        ]
        with self.assertRaisesRegex(RuntimeError, 'Docker operation failed'):
            self.fixture.inspect_owned({'kind': 'container', 'name': 'gone'})
        self.assertEqual(docker.call_args_list[0].args[0], 'container')
        self.assertEqual(docker.call_args_list[1].args[:3], ('container', 'ls', '-a'))

    @patch.object(n2, 'docker')
    def test_failed_inspect_with_name_still_listed_is_not_absence(self, docker):
        docker.side_effect = [
            subprocess.CompletedProcess([], 1, '', ''),
            subprocess.CompletedProcess([], 0, 'still-here\n', ''),
        ]
        with self.assertRaisesRegex(ValueError, 'ownership cannot be verified'):
            self.fixture.inspect_owned({'kind': 'container', 'name': 'still-here'})

    @patch.object(n2, 'docker')
    def test_label_mismatch_is_rejected(self, docker):
        item = self.owned_container('app')
        item['Config']['Labels'][n2.OWNER] = '/another/fixture'
        docker.return_value = subprocess.CompletedProcess([], 0, json.dumps([item]), '')
        with self.assertRaisesRegex(ValueError, 'ownership mismatch'):
            self.fixture.inspect_owned({'kind': 'container', 'name': 'app'})

    @patch.object(n2, 'docker')
    def test_recorded_container_id_mismatch_is_rejected(self, docker):
        docker.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps([self.owned_container('app', 'new-id')]), '')
        with self.assertRaisesRegex(ValueError, 'Container ID changed'):
            self.fixture.inspect_owned({'kind': 'container', 'name': 'app', 'id': 'old-id'})

    @patch.object(n2, 'docker')
    def test_partial_create_is_saved_before_docker_failure(self, docker):
        docker.side_effect = RuntimeError('create failed')
        with self.assertRaisesRegex(RuntimeError, 'create failed'):
            self.fixture.add('volume', 'partial-volume', ['volume', 'create', 'partial-volume'])
        saved = json.loads((self.directory / 'state.json').read_text())
        self.assertEqual(saved['resources'], [{'kind': 'volume', 'name': 'partial-volume'}])

    @patch.object(n2, 'docker')
    def test_app_stop_failure_continues_other_app_and_preserves_postgres_and_storage(self, docker):
        resources = [
            {'kind': 'container', 'name': 'app-a'},
            {'kind': 'container', 'name': 'app-b'},
            {'kind': 'container', 'name': 'postgres'},
            {'kind': 'volume', 'name': 'test-data'},
            {'kind': 'volume', 'name': 'test-secrets'},
            {'kind': 'network', 'name': 'test-network'},
        ]
        self.state['resources'] = resources
        self.fixture.save()

        def remove_container(resource):
            if resource['name'] == 'app-a':
                raise RuntimeError('stop failed')
            if resource['name'] == 'app-b':
                return {'name': resource['name'], 'exitCode': 0, 'oomKilled': False}
            self.fail('PostgreSQL must be preserved after an app cleanup failure')

        attempted = []
        def track_remove_container(resource):
            attempted.append(resource['name'])
            return remove_container(resource)
        self.fixture.remove_container = track_remove_container
        result = self.fixture.cleanup()
        self.assertEqual([r['name'] for r in result['objects']], ['app-b'])
        self.assertEqual([r['name'] for r in result['errors']], ['app-a'])
        self.assertEqual(attempted, ['app-a', 'app-b'])
        self.assertFalse(result['privateDirectoryRemoved'])
        self.assertTrue(self.directory.exists())
        docker.assert_not_called()

    @patch.object(n2.urllib.request, 'urlopen')
    @patch.object(n2, 'docker')
    def test_unexpected_published_port_fails_readiness_and_keeps_recovery_state(self, docker, urlopen):
        self.state.update(runtime='runtime-image', network='fixture-network',
                          secrets_volume='fixture-secrets')
        # add() records the container before the mocked create call returns its ID.
        docker.side_effect = [
            subprocess.CompletedProcess([], 0, 'new-container-id\n', ''),
            subprocess.CompletedProcess([], 0, '', ''),
        ]
        wrong_port_item = self.owned_container('idp-n2-linux-' + self.state['nonce'] + '-browser')
        wrong_port_item['State']['Running'] = True
        wrong_port_item['NetworkSettings'] = {'Ports': {'8080/tcp': [
            {'HostIp': '0.0.0.0', 'HostPort': '43210'}]}}
        with patch.object(self.fixture, 'write_config'), \
             patch.object(self.fixture, 'inspect_owned', return_value=wrong_port_item), \
             patch.object(n2.time, 'sleep'):
            urlopen.return_value.__enter__.return_value.status = 200
            with self.assertRaisesRegex(ValueError, 'Unexpected published port'):
                self.fixture.launch('browser', {
                    'runtime': {'http': {'browser_origin': 'http://127.0.0.1:43210'}},
                    'management': {'mount_prefix': '/identity'},
                })
        self.assertEqual(self.state['resources'][0]['id'], 'new-container-id')
        self.assertEqual(self.state['hosts']['browser']['containerId'], 'new-container-id')
        self.assertTrue((self.directory / 'state.json').exists())

    @patch.object(n2, 'docker')
    def test_container_create_port_bind_failure_keeps_partial_resource_record(self, docker):
        self.state.update(runtime='runtime-image', network='fixture-network',
                          secrets_volume='fixture-secrets')
        docker.side_effect = RuntimeError('Docker operation failed: container')
        with patch.object(self.fixture, 'write_config'):
            with self.assertRaisesRegex(RuntimeError, 'Docker operation failed'):
                self.fixture.launch('browser', {
                    'runtime': {'http': {'browser_origin': 'http://127.0.0.1:43210'}},
                    'management': {'mount_prefix': '/identity'},
                })
        self.assertEqual(self.state['resources'], [{
            'kind': 'container', 'name': 'idp-n2-linux-' + self.state['nonce'] + '-browser',
        }])
        self.assertTrue((self.directory / 'state.json').exists())

    @patch.object(n2, 'docker')
    def test_once_failure_keeps_log_and_restart_replaces_old_resource_record(self, docker):
        self.state.update(network='fixture-network', secrets_volume='fixture-secrets',
                          prepare='prepare-image')
        failed_create = subprocess.CompletedProcess([], 0, 'prepare-id\n', '')
        failed_start = subprocess.CompletedProcess([], 7, 'stdout detail', 'stderr detail')
        docker.side_effect = [failed_create, failed_start]
        inspected = self.owned_container('prepare-container', 'prepare-id')
        inspected['State']['ExitCode'] = 7
        with patch.object(self.fixture, 'inspect_owned', return_value=inspected):
            with self.assertRaisesRegex(RuntimeError, 'Preparation command failed'):
                self.fixture.once(['/bin/false'])

        resource = self.state['resources'][0]
        self.assertEqual(resource['id'], 'prepare-id')
        log_path = self.directory / (resource['name'] + '.log')
        self.assertEqual(log_path.read_text(), 'stdout detailstderr detail')
        self.assertIn(resource, json.loads((self.directory / 'state.json').read_text())['resources'])

        config_path = self.directory / 'browser.json'
        config_path.write_text('{"restart": true}')
        old = {'kind': 'container', 'name': 'old-app', 'id': 'old-id'}
        self.state['resources'] = [old]
        self.state['hosts']['browser'] = {'container': 'old-app', 'config': str(config_path),
                                          'origin': 'http://127.0.0.1:43210', 'mount': '/identity',
                                          'ui': '/console'}

        def relaunch(label, config):
            self.assertEqual(label, 'browser')
            self.assertEqual(config, {'restart': True})
            self.assertNotIn(old, self.state['resources'])
            self.state['resources'].append({'kind': 'container', 'name': 'new-app', 'id': 'new-id'})

        with patch.object(self.fixture, 'remove_container', return_value={
                'name': 'old-app', 'exitCode': 0, 'oomKilled': False}) as remove, \
             patch.object(self.fixture, 'launch', side_effect=relaunch):
            result = self.fixture.restart('browser')
        remove.assert_called_once_with(old)
        self.assertTrue(result['sameOrigin'])
        self.assertEqual([r['name'] for r in self.state['resources']], ['new-app'])

    def test_config_uses_fixture_secret_file_references_and_private_mode(self):
        self.state['schemas'] = {'enabled': 'schema-test'}
        class BoundSocketStub:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def bind(self, _address):
                pass
            def getsockname(self):
                return ('127.0.0.1', 43210)

        with patch.object(n2.socket, 'socket', return_value=BoundSocketStub()):
            config = self.fixture.config('enabled', 'fixed', {'kind': 'fixed', 'tenant_id': 'tenant-a'})
        old_umask = os.umask(0o077)
        try:
            with patch.object(self.fixture, 'once') as once:
                self.fixture.write_config('fixed', config)
                once.assert_called_once()
        finally:
            os.umask(old_umask)
        path = self.directory / 'fixed.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        config = json.loads(path.read_text())
        encoded = json.dumps(config)
        self.assertIn('/run/idp/secrets/key.der', encoded)
        self.assertIn('/run/idp/secrets/database-uri', encoded)
        self.assertEqual(config['runtime']['postgres']['connection']['schema_name'], 'schema-test')
        self.assertNotIn('postgresql://', encoded)


if __name__ == '__main__':
    unittest.main()
