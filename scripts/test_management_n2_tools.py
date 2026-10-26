"""Offline failure-path checks for isolated management fixture tooling."""
import ast
import contextlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parent.parent


class ManagementFixtureToolTests(unittest.TestCase):
    def run_preparation_failure(self, directory, children, cleanup_error=None):
        tree = ast.parse((ROOT / "scripts/prepare_management_navigation.py").read_text())
        handler = next(n for n in tree.body if isinstance(n, ast.Try)).handlers[0]
        code = compile(ast.Module(body=handler.body, type_ignores=[]), "prepare-failure-cleanup", "exec")
        cleanup = Mock()
        def checked_cleanup(state_file):
            self.assertEqual(Path(state_file), directory / "state.json")
            if cleanup_error:
                raise cleanup_error
            shutil.rmtree(directory)
        cleanup.side_effect = checked_cleanup
        env = {"directory": directory, "container": "idp-ui-b-123abc", "children": children,
               "json": json, "subprocess": Mock(TimeoutExpired=subprocess.TimeoutExpired),
               "cleanup": cleanup, "shutil": shutil, "sys": __import__("sys")}
        original = RuntimeError("preparation failed")
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                raise original
            except RuntimeError:
                with self.assertRaises(RuntimeError) as caught:
                    exec(code, env)
        self.assertIs(caught.exception, original)
        return cleanup

    def test_host_timeout_attempts_other_children_and_keeps_recovery_state(self):
        with tempfile.TemporaryDirectory(prefix="idp-n2-tools-") as temp:
            directory = Path(temp)
            first, second = Mock(pid=101, args=["host", "--config", str(directory / "a.json")]), Mock(pid=102, args=["host", "--config", str(directory / "b.json")])
            for child in [first, second]:
                child.poll.return_value = None
            first.wait.side_effect = subprocess.TimeoutExpired("host", 10)
            cleanup = self.run_preparation_failure(directory, [first, second])
            first.terminate.assert_called_once(); second.terminate.assert_called_once()
            second.wait.assert_called_once_with(timeout=10)
            cleanup.assert_not_called()
            state = json.loads((directory / "state.json").read_text())
            self.assertEqual(state["hosts"]["1"], {"pid": 102, "config": str(directory / "b.json")})

    def test_preparation_failure_uses_ownership_checked_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="idp-n2-tools-") as temp:
            for should_fail in [True, False]:
                directory = Path(temp) / str(should_fail); directory.mkdir()
                error = RuntimeError("cleanup rejected ownership") if should_fail else None
                cleanup = self.run_preparation_failure(directory, [], error)
                cleanup.assert_called_once_with(directory / "state.json")
                self.assertEqual(directory.exists(), should_fail)

    def test_cleanup_rejects_different_container_label_without_removing_it(self):
        tree = ast.parse((ROOT / "scripts/prepare_management_navigation.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "cleanup")
        with tempfile.TemporaryDirectory(prefix="idp-ui-b-", dir=tempfile.gettempdir()) as temp:
            directory = Path(temp).resolve(); state_file = directory / "state.json"
            state_file.write_text(json.dumps({"dir": str(directory), "container": "idp-ui-b-123abc", "hosts": {}}))
            docker = Mock(run=Mock(return_value=Mock(returncode=0, stdout="/different-fixture\n")))
            env = {"pathlib": __import__("pathlib"), "tempfile": tempfile, "json": json, "re": re,
                   "subprocess": docker, "shutil": shutil, "time": __import__("time")}
            exec(compile(ast.Module(body=[function], type_ignores=[]), "standard-cleanup", "exec"), env)
            with self.assertRaisesRegex(ValueError, "ownership label"):
                env["cleanup"](state_file)
            docker.run.assert_called_once()
            self.assertEqual(docker.run.call_args.args[0][:2], ["docker", "inspect"])
            self.assertFalse(any(call.args[0][:2] == ["docker", "rm"] for call in docker.run.call_args_list))
            self.assertTrue(state_file.exists())

    def test_standard_cleanup_recovers_absent_container_but_keeps_files_on_outage(self):
        tree = ast.parse((ROOT / "scripts/prepare_management_navigation.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "cleanup")
        with tempfile.TemporaryDirectory(prefix="idp-ui-b-", dir=tempfile.gettempdir()) as temp:
            directory = Path(temp).resolve(); state_file = directory / "state.json"
            state_file.write_text(json.dumps({"dir": str(directory), "container": "idp-ui-b-123abc", "hosts": {}}))
            docker = Mock(run=Mock(return_value=Mock(returncode=1)), DEVNULL=subprocess.DEVNULL,
                          check_output=Mock(side_effect=subprocess.CalledProcessError(1, "docker ps")))
            env = {"pathlib": __import__("pathlib"), "tempfile": tempfile, "json": json, "re": re,
                   "subprocess": docker, "shutil": shutil, "time": __import__("time")}
            exec(compile(ast.Module(body=[function], type_ignores=[]), "standard-cleanup", "exec"), env)
            with self.assertRaises(subprocess.CalledProcessError):
                env["cleanup"](state_file)
            self.assertTrue(state_file.exists())
            docker.check_output.side_effect = None; docker.check_output.return_value = "unverified-container"
            with self.assertRaises(ValueError): env["cleanup"](state_file)
            self.assertTrue(state_file.exists())
            docker.check_output.return_value = ""
            with contextlib.redirect_stdout(io.StringIO()): env["cleanup"](state_file)
            self.assertFalse(directory.exists())


if __name__ == "__main__":
    unittest.main()
