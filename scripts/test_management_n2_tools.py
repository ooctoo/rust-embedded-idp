"""Offline failure-path checks for the disposable N2 Mac tooling."""
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


class N2ToolTests(unittest.TestCase):
    def run_preparation_failure(self, directory, children, docker_status):
        tree = ast.parse((ROOT / "scripts/prepare_management_navigation.py").read_text())
        handler = next(n for n in tree.body if isinstance(n, ast.Try)).handlers[0]
        code = compile(ast.Module(body=handler.body, type_ignores=[]), "prepare-failure-cleanup", "exec")
        docker = Mock(return_value=Mock(returncode=docker_status))
        env = {"directory": directory, "container": "idp-ui-b-123abc", "children": children,
               "json": json, "subprocess": Mock(TimeoutExpired=subprocess.TimeoutExpired, run=docker),
               "shutil": shutil, "sys": __import__("sys")}
        original = RuntimeError("preparation failed")
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                raise original
            except RuntimeError:
                with self.assertRaises(RuntimeError) as caught:
                    exec(code, env)
        self.assertIs(caught.exception, original)
        return docker

    def test_host_timeout_attempts_other_children_and_keeps_recovery_state(self):
        with tempfile.TemporaryDirectory(prefix="idp-n2-tools-") as temp:
            directory = Path(temp)
            first, second = Mock(pid=101, args=["host", "--config", str(directory / "a.json")]), Mock(pid=102, args=["host", "--config", str(directory / "b.json")])
            for child in [first, second]:
                child.poll.return_value = None
            first.wait.side_effect = subprocess.TimeoutExpired("host", 10)
            docker = self.run_preparation_failure(directory, [first, second], 0)
            first.terminate.assert_called_once(); second.terminate.assert_called_once()
            second.wait.assert_called_once_with(timeout=10)
            docker.assert_not_called()
            state = json.loads((directory / "state.json").read_text())
            self.assertEqual(state["hosts"]["1"], {"pid": 102, "config": str(directory / "b.json")})

    def test_failed_container_removal_keeps_files_and_success_removes_them(self):
        with tempfile.TemporaryDirectory(prefix="idp-n2-tools-") as temp:
            for status in [1, 0]:
                directory = Path(temp) / str(status); directory.mkdir()
                docker = self.run_preparation_failure(directory, [], status)
                docker.assert_called_once()
                self.assertEqual(directory.exists(), status != 0)

    def test_diagnostics_redact_credentials_paths_and_data_modules(self):
        tree = ast.parse((ROOT / "scripts/run_management_n2_mac.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "redact")
        env = {"ROOT": ROOT, "Path": Path, "tempfile": tempfile, "re": re}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "redact", "exec"), env)
        original = f"{ROOT}/scripts/test.mjs {Path.home()}/.npm/cache {Path(tempfile.gettempdir()).resolve()}/idp-ui-b-owned secret-token data:text/javascript;base64,YWJj:42:1"
        result = env["redact"](original, ["secret-token"])
        self.assertNotIn(str(Path.home()), result); self.assertNotIn(str(ROOT), result)
        self.assertNotIn("secret-token", result); self.assertNotIn("YWJj", result)
        self.assertIn("[source omitted]:42:1", result)

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

    def test_profile_cleanup_continues_and_records_failures(self):
        # Execute the real finalizer against owned-profile doubles; never launch
        # Chrome, Docker or remove a real browser directory in this offline test.
        result = subprocess.run(["node", "--input-type=module"], cwd=ROOT, text=True, capture_output=True, input=r'''
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const source = await readFile('scripts/check_management_n2_mac.mjs', 'utf8');
const body = source.slice(source.indexOf('} finally {\n  let profilesRemoved') + '} finally {'.length, source.lastIndexOf('}'));
assert.ok(body.includes('cleanupErrors'));
const run = new (Object.getPrototypeOf(async function(){}).constructor)('contexts', 'rm', 'writeFile', 'output', 'browserVersion', 'cases', 'pageErrors', 'refreshResponses', 'failure', 'console', body);
let closed = [], removed = [], saved;
const contexts = [0,1,2].map(index => ({profile:`owned-${index}`, context:{close: async()=>{closed.push(index); if(index===0)throw Error('close failed');}}}));
await assert.rejects(run(contexts, async profile=>{removed.push(profile); if(profile==='owned-2')throw Error('remove failed');}, async(_p,data)=>{saved=JSON.parse(data);}, 'out', 'synthetic', Array(8).fill('case'), [], [], undefined, {error(){}}), /cleanup failed/);
assert.deepEqual(closed,[0,1,2]); assert.deepEqual(removed,['owned-1','owned-2']);
assert.equal(saved.profilesRemoved,1); assert.equal(saved.cleanupErrors.length,2); assert.equal(saved.complete,false);
await run([], async()=>{}, async(_p,data)=>{saved=JSON.parse(data);}, 'out', 'synthetic', Array(8).fill('case'), [], [], undefined, {error(){}});
assert.equal(saved.complete,true);
''')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
