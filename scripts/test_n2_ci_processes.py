"""Offline mocked process ownership/deadline checks; no business services launched."""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import n2_ci_runtime as runtime


def record(pid, ppid, pgid=None, ticks=None):
    return {'pid': pid, 'ppid': ppid, 'pgid': pid if pgid is None else pgid,
            'startTicks': str(pid) if ticks is None else ticks}


class ProcessOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start(); self.addCleanup(self.environment.stop)

    def test_dead_leader_with_surviving_group_is_not_signalled_without_identity(self):
        with patch.object(runtime, 'process_identity', return_value=None), \
             patch.object(runtime, 'process_snapshot', return_value={30: record(30, 1, 20)}), \
             patch.object(runtime.os, 'killpg') as killpg:
            with self.assertRaisesRegex(RuntimeError, 'cannot establish group ownership'):
                runtime.stop_process_group(Mock(pid=20), identity='original')
            killpg.assert_called_once_with(20, 0)

    def test_linux_zombie_only_group_is_confirmed_without_signalling(self):
        process = Mock(pid=20)
        with patch.object(runtime.sys, 'platform', 'linux'), \
             patch.object(runtime, 'process_identity', return_value=None), \
             patch.object(runtime, 'process_snapshot', return_value={}) as snapshot, \
             patch.object(runtime.os, 'killpg') as killpg:
            runtime.stop_process_group(process, identity='original')
        snapshot.assert_called_once_with(strict=True)
        killpg.assert_called_once_with(20, 0)
        process.wait.assert_called_once()

    def test_linux_live_group_member_is_not_treated_as_exit(self):
        with patch.object(runtime.sys, 'platform', 'linux'), \
             patch.object(runtime, 'process_snapshot', return_value={30: record(30, 1, 20)}), \
             patch.object(runtime.os, 'killpg'):
            self.assertTrue(runtime.process_group_alive(20))

    def test_linux_group_inventory_failure_cannot_confirm_exit(self):
        with patch.object(runtime.sys, 'platform', 'linux'), \
             patch.object(Path, 'iterdir', side_effect=PermissionError), \
             patch.object(runtime.os, 'killpg'):
            with self.assertRaisesRegex(RuntimeError, 'inventory is unavailable'):
                runtime.process_group_alive(20)

    def test_strict_process_record_rejects_unreadable_and_malformed_state(self):
        for error in [PermissionError, ValueError]:
            with self.subTest(error=error.__name__), \
                 patch.object(Path, 'read_text', side_effect=error):
                with self.assertRaisesRegex(RuntimeError, 'process record unavailable'):
                    runtime.process_record(20, strict=True)

    def test_unknown_identity_kills_group_only_while_direct_child_pid_is_owned(self):
        process = Mock(pid=20)
        with patch.object(runtime.os, 'kill') as kill, \
             patch.object(runtime.os, 'killpg', side_effect=[None, ProcessLookupError]) as killpg:
            runtime.stop_process_group(process)
        kill.assert_called_once_with(20, 0)
        self.assertEqual(killpg.call_args_list[0].args, (20, signal.SIGKILL))
        self.assertEqual(killpg.call_args_list[1].args, (20, 0))
        process.wait.assert_called_once()

    def test_stat_reads_ancestry_and_identity_and_ignores_zombies(self):
        fields = ['S', '5', '9'] + ['0'] * 16 + ['12345']
        with patch.object(Path, 'read_text', return_value='9 (name with ) spaces) ' + ' '.join(fields)) as read:
            self.assertEqual(runtime.process_record(9), record(9, 5, 9, '12345'))
            self.assertEqual(read.call_count, 1)
        fields[0] = 'Z'
        with patch.object(Path, 'read_text', return_value='9 (zombie) ' + ' '.join(fields)):
            self.assertIsNone(runtime.process_identity(9))
        with patch.object(Path, 'read_text', side_effect=FileNotFoundError):
            self.assertIsNone(runtime.process_identity(9))

    def test_ci_process_record_fails_closed_for_permission_and_malformed_data(self):
        with patch.dict(os.environ, {'IDP_UI_PROFILE': 'ci-functional'}), \
             patch.object(Path, 'read_text', side_effect=PermissionError):
            with self.assertRaisesRegex(RuntimeError, r'pid 9: PermissionError'):
                runtime.process_identity(9)
        with patch.dict(os.environ, {'IDP_UI_PROFILE': 'ci-functional'}), \
             patch.object(Path, 'read_text', return_value='9 (broken) S 5'):
            with self.assertRaisesRegex(RuntimeError, r'pid 9: (IndexError|ValueError)'):
                runtime.process_identity(9)
        with patch.object(Path, 'read_text', side_effect=PermissionError):
            self.assertIsNone(runtime.process_identity(9))  # Preserve non-CI behavior.

    def test_ci_tracked_child_read_failure_is_not_treated_as_exit(self):
        child = record(20, 10, ticks='child')
        with patch.dict(os.environ, {'IDP_UI_PROFILE': 'ci-functional'}), \
             patch.object(runtime, 'process_identity', side_effect=RuntimeError('unreadable')):
            with self.assertRaisesRegex(RuntimeError, 'unreadable'):
                runtime.live_descendants({20: child})

    def test_missing_proc_inventory_fails_closed_in_ci(self):
        with patch.dict(os.environ, {'IDP_UI_PROFILE': 'ci-functional'}), \
             patch.object(Path, 'iterdir', side_effect=PermissionError):
            with self.assertRaisesRegex(RuntimeError, 'inventory is unavailable'):
                runtime.process_snapshot()

    def test_detached_descendants_are_captured_without_unrelated_processes(self):
        root = record(10, 1, 10, 'root')
        child = record(20, 10, 20, 'child')  # setsid / detached browser
        grandchild = record(30, 20, 20, 'grandchild')
        unrelated = record(40, 1, 40, 'unrelated')
        tracked = {}
        with patch.object(runtime, 'process_snapshot', return_value={r['pid']: r for r in [root, grandchild, child, unrelated]}), \
             patch.object(runtime, 'register_identity') as register:
            runtime.track_descendants(root, tracked)
        self.assertEqual(set(tracked), {20, 30})
        self.assertEqual({call.args[0]['pid'] for call in register.call_args_list}, {20, 30})
        self.assertTrue(all(set(call.args[0]) == {'pid', 'pgid', 'startTicks'} for call in register.call_args_list))

    def test_known_child_still_tracks_descendants_after_root_exits(self):
        root = record(10, 1, ticks='root')
        child = record(20, 1, ticks='child')
        grandchild = record(30, 20, ticks='grandchild')
        tracked = {20: child}
        with patch.object(runtime, 'process_snapshot', return_value={20: child, 30: grandchild}), \
             patch.object(runtime, 'register_identity'):
            runtime.track_descendants(root, tracked)
        self.assertEqual(set(tracked), {20, 30})

    def test_reused_pid_is_never_signalled_or_used_as_an_ancestry_root(self):
        root = record(10, 1, ticks='root')
        tracked = {20: record(20, 10, ticks='original')}
        reused = record(20, 1, ticks='replacement')
        foreign = record(30, 20, ticks='foreign')
        with patch.object(runtime, 'process_snapshot', return_value={20: reused, 30: foreign}), \
             patch.object(runtime, 'register_identity') as register:
            runtime.track_descendants(root, tracked)
            register.assert_not_called()
        with patch.object(runtime, 'process_identity', return_value='replacement'), patch.object(runtime.os, 'kill') as kill:
            runtime.stop_descendants(tracked)
            kill.assert_not_called()
        with patch.object(runtime, 'process_identity', return_value='replacement'), patch.object(runtime.os, 'killpg') as killpg:
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                runtime.stop_process_group(Mock(pid=20), identity='original')
            killpg.assert_not_called()

    def test_descendant_term_then_kill_is_bounded_and_confirms_exit(self):
        tracked = {20: record(20, 10, ticks='child')}
        alive = True
        def identity(_pid): return 'child' if alive else None
        def kill(pid, sig):
            nonlocal alive
            self.assertEqual(pid, 20)
            if sig == signal.SIGKILL: alive = False
        with patch.object(runtime, 'process_identity', side_effect=identity), \
             patch.object(runtime.os, 'kill', side_effect=kill) as signal_process, \
             patch.object(runtime.time, 'monotonic', side_effect=itertools.count(0, 3)):
            runtime.stop_descendants(tracked)
        self.assertEqual([call.args[1] for call in signal_process.call_args_list], [signal.SIGTERM, signal.SIGKILL])

    def test_signal_failure_cannot_be_reported_as_cleanup_success(self):
        tracked = {20: record(20, 10, ticks='child')}
        with patch.object(runtime, 'process_identity', return_value='child'), \
             patch.object(runtime.os, 'kill', side_effect=PermissionError) as kill, \
             patch.object(runtime.time, 'monotonic', side_effect=itertools.count(0, 3)):
            with self.assertRaisesRegex(RuntimeError, 'exit could not be confirmed.*PermissionError'):
                runtime.stop_descendants(tracked)
        self.assertEqual([call.args[1] for call in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])

    def test_registry_contains_exact_pid_identity_and_private_mode(self):
        with tempfile.TemporaryDirectory(prefix='n2-process-mock-') as temporary:
            path = Path(temporary) / 'processes.jsonl'
            with patch.dict(os.environ, {'IDP_N2_PROCESS_REGISTRY': str(path)}):
                runtime.register_identity({'pid': 20, 'pgid': 20, 'startTicks': 'child'})
            self.assertEqual(json.loads(path.read_text())['pid'], 20)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class BoundedRunTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start(); self.addCleanup(self.environment.stop)
        self.process = Mock(pid=10, returncode=0)
        self.process.communicate.return_value = ('output', None)

    def patches(self):
        self.addCleanup(patch.stopall)
        patch.object(runtime, 'register_identity').start()
        patch.object(runtime, 'process_identity', return_value='root').start()
        self.track = patch.object(runtime, 'track_descendants').start()
        self.popen = patch.object(runtime.subprocess, 'Popen', return_value=self.process).start()
        patch.object(runtime.os, 'killpg', side_effect=ProcessLookupError).start()

    def test_expired_deadline_is_rejected_before_spawn(self):
        with patch.dict(os.environ, {'IDP_N2_DEADLINE': '1'}), \
             patch.object(runtime.time, 'monotonic', return_value=2), \
             patch.object(runtime.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(TimeoutError, 'deadline exceeded'):
                runtime.run_bounded(['node', 'not-started'])
            popen.assert_not_called()

    def test_initial_identity_read_failure_still_cleans_spawned_process(self):
        self.patches()
        with patch.object(runtime, 'process_identity', side_effect=RuntimeError('unreadable identity')) as identity, \
             patch.object(runtime.os, 'kill'), \
             patch.object(runtime.os, 'killpg', side_effect=[None, ProcessLookupError]) as group:
            with self.assertRaisesRegex(RuntimeError, 'unreadable identity'):
                runtime.run_bounded(['node', 'checker'])
        identity.assert_called_once_with(self.process.pid)
        self.assertEqual(group.call_args_list[0].args, (self.process.pid, signal.SIGKILL))
        self.assertEqual(group.call_args_list[1].args, (self.process.pid, 0))

    def test_post_exit_tracked_identity_failure_runs_cleanup(self):
        self.patches()
        with patch.object(runtime, 'live_descendants', side_effect=RuntimeError('unreadable child identity')), \
             patch.object(runtime, 'stop_descendants') as descendants, \
             patch.object(runtime, 'stop_process_group') as group:
            with self.assertRaisesRegex(RuntimeError, 'unreadable child identity'):
                runtime.run_bounded(['node', 'checker'])
        descendants.assert_called_once()
        group.assert_called_once()

    def test_communicate_sampling_uses_first_input_once_and_merged_stderr(self):
        self.patches()
        self.process.communicate.side_effect = [subprocess.TimeoutExpired('node', .1), ('output', None)]
        with patch.object(runtime, 'live_descendants', return_value=[]):
            result = runtime.run_bounded(['node', 'checker'], input='private stdin', stderr=subprocess.STDOUT)
        self.assertEqual(result.stdout, 'output')
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.process.communicate.call_args_list[0].kwargs['input'], 'private stdin')
        self.assertIsNone(self.process.communicate.call_args_list[1].kwargs['input'])
        self.assertTrue(all(call.kwargs['timeout'] <= .1 for call in self.process.communicate.call_args_list))
        self.assertGreaterEqual(self.track.call_count, 3)
        self.assertEqual(self.popen.call_args.kwargs['stderr'], subprocess.STDOUT)
        self.assertTrue(self.popen.call_args.kwargs['start_new_session'])

    def test_normal_orphan_is_cleaned_and_never_reported_as_passed(self):
        self.patches()
        with patch.object(runtime, 'live_descendants', return_value=[record(20, 1)]), \
             patch.object(runtime, 'stop_descendants') as descendants, \
             patch.object(runtime, 'stop_process_group') as group:
            with self.assertRaisesRegex(RuntimeError, 'left owned descendants'):
                runtime.run_bounded(['node', 'checker'])
        descendants.assert_called_once(); group.assert_called_once()

    def test_detached_timeout_cleans_descendants_before_parent_group(self):
        self.patches()
        calls = []
        self.process.communicate.side_effect = subprocess.TimeoutExpired('node', .1, output=b'partial')
        with patch.object(runtime.time, 'monotonic', side_effect=itertools.count(0, 1)), \
             patch.object(runtime, 'command_timeout', return_value=2.5), \
             patch.object(runtime, 'stop_descendants', side_effect=lambda _: calls.append('children')), \
             patch.object(runtime, 'stop_process_group', side_effect=lambda *a, **kw: calls.append('group')):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                runtime.run_bounded(['node', 'checker'])
        self.assertEqual(calls, ['children', 'group'])
        self.assertEqual(caught.exception.output, b'partial')
        self.assertEqual(caught.exception.timeout, 2.5)

    def test_interrupt_cleans_descendants_and_parent_even_when_child_stop_fails(self):
        self.patches()
        self.process.communicate.side_effect = KeyboardInterrupt
        with patch.object(runtime, 'stop_descendants', side_effect=RuntimeError('unconfirmed')), \
             patch.object(runtime, 'stop_process_group') as group:
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                runtime.run_bounded(['node', 'checker'])
            group.assert_called_once()

    def test_nonzero_exit_retains_subprocess_check_behavior(self):
        self.patches()
        self.process.returncode = 2
        with patch.object(runtime, 'live_descendants', return_value=[]):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                runtime.run_bounded(['node', 'checker'], check=True)
        self.assertEqual(caught.exception.returncode, 2)
        self.assertEqual(caught.exception.output, 'output')

    def test_group_cleanup_failure_is_not_masked(self):
        self.patches()
        self.process.communicate.side_effect = KeyboardInterrupt
        with patch.object(runtime, 'stop_descendants'), \
             patch.object(runtime, 'stop_process_group', side_effect=PermissionError):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed.*PermissionError'):
                runtime.run_bounded(['node', 'checker'])


if __name__ == '__main__':
    unittest.main()
