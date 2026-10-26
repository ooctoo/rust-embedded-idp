"""Offline failure-path checks for the disposable Postgres integration runner."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "ci-quality" / "integration.py"
SPEC = importlib.util.spec_from_file_location("ci_integration", RUNNER_PATH)
assert SPEC and SPEC.loader
ci = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ci
SPEC.loader.exec_module(ci)


FAKE_DOCKER = r'''#!/bin/bash
set -euo pipefail
state="${FAKE_DOCKER_STATE:?}"
case "$1" in
  image)
    printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
    ;;
  run)
    shift
    while (($#)); do
      case "$1" in
        --name) container="$2"; shift 2 ;;
        --label) owner="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '%s\n%s\n' "$container" "$owner" > "$state"
    printf 'fake-container-id\n'
    ;;
  port) printf '127.0.0.1:54321\n' ;;
  exec)
    if [[ "${@: -2:1}" == postgres ]]; then printf 'postgres (PostgreSQL) 18.6\n'; fi
    exit 0
    ;;
  ps)
    if [[ -f "$state" ]]; then sed -n '1p' "$state"; fi
    ;;
  inspect)
    owner="$(sed -n '2s/^[^=]*=//p' "$state")"
    if [[ "${FAKE_OWNER_MISMATCH:-0}" == 1 ]]; then owner=some-other-run; fi
    printf '{"ci.integration.owner":"%s"}\n' "$owner"
    ;;
  rm)
    if [[ "${FAKE_CLEANUP_FAIL:-0}" == 1 ]]; then echo 'simulated removal failure' >&2; exit 19; fi
    rm -f "$state"
    ;;
  *) echo "unexpected docker subcommand" >&2; exit 64 ;;
esac
'''


class IntegrationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ci-integration-offline-")
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "docker-state"
        self.output = self.root / "evidence"
        self.write_executable("docker", FAKE_DOCKER)
        self.write_executable("pnpm", "#!/bin/bash\necho 'fake web build'\n")
        self.write_executable("rustc", "#!/bin/bash\necho 'rustc fixture'\n")
        self.write_executable("node", "#!/bin/bash\necho 'v22.23.4'\n")
        self.write_executable("git", "#!/bin/bash\n[[ $1 != rev-parse ]] || echo 1111111111111111111111111111111111111111\n")
        self.write_executable("cargo", "#!/bin/bash\n"
                              "printf 'test URI: %s\\n' \"$EMBEDDED_IDP_TEST_PG_CONNECTION_URI\"\n"
                              "if [[ \"${FAKE_CARGO_NO_SUMMARIES:-0}\" != 1 ]]; then\n"
                              "  while (($#)); do\n"
                              "    [[ $1 == --test ]] || { shift; continue; }; shift; index=$1; shift\n"
                              "    echo \"Running tests/${index}.rs (target/debug/deps/${index})\"\n"
                              "    echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'\n"
                              "  done\n"
                              "fi\n"
                              "if [[ \"${FAKE_CARGO_SLEEP:-0}\" == 1 ]]; then touch \"$FAKE_CARGO_STARTED\"; sleep 30; fi\n"
                              "[[ \"${FAKE_CARGO_FAIL:-0}\" != 1 ]]\n")
        self.environment = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_DOCKER_STATE": str(self.state),
            "FAKE_CARGO_STARTED": str(self.root / "cargo-started"),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def write_executable(self, name: str, body: str):
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o700)

    def invoke(self, *, environment=None):
        return subprocess.run(
            [sys.executable, str(RUNNER_PATH), "--output-dir", str(self.output)],
            cwd=ROOT,
            env=environment or self.environment,
            text=True,
            capture_output=True,
            timeout=20,
        )

    def result(self):
        return json.loads((self.output / "integration-result.json").read_text(encoding="utf-8"))

    def test_missing_docker_fails_and_writes_result(self):
        environment = {**self.environment, "PATH": str(self.bin)}
        (self.bin / "docker").unlink()
        result = self.invoke(environment=environment)
        self.assertEqual(result.returncode, 1, result.stderr)
        evidence = self.result()
        self.assertEqual(evidence["status"], "failed")
        self.assertIn("docker", evidence["failure"])
        self.assertEqual(evidence["cleanup"], "confirmed")
        self.assertTrue((self.output / "integration.log").exists())

    def test_pass_redacts_connection_uri_and_confirms_cleanup(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = self.result()
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(evidence["cleanup"], "confirmed")
        self.assertEqual(len(evidence["testTargets"]), 10)
        self.assertTrue(all(target["passed"] > 0 and target["ignored"] == 0 for target in evidence["testTargets"]))
        self.assertTrue(evidence["sourceSha"])
        self.assertTrue(evidence["postgresImageId"])
        log = (self.output / "integration.log").read_text(encoding="utf-8")
        self.assertIn("[REDACTED]", log)
        self.assertNotIn("postgres://ci_integration:", log)
        self.assertNotIn("POSTGRES_PASSWORD=", log)
        self.assertFalse(self.state.exists())

    def test_live_check_failure_stays_red_and_cleans_container(self):
        environment = {**self.environment, "FAKE_CARGO_FAIL": "1"}
        result = self.invoke(environment=environment)
        self.assertEqual(result.returncode, 1)
        evidence = self.result()
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["cleanup"], "confirmed")
        self.assertIn("live Postgres checks failed", evidence["failure"])
        self.assertFalse(self.state.exists())
        self.assertNotIn("postgres://ci_integration:", (self.output / "integration.log").read_text())

    def test_cleanup_failure_fails_even_when_checks_pass(self):
        environment = {**self.environment, "FAKE_CLEANUP_FAIL": "1"}
        result = self.invoke(environment=environment)
        self.assertEqual(result.returncode, 1)
        evidence = self.result()
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["cleanup"], "not_confirmed")
        self.assertIn("cleanup failed", evidence["failure"])
        recovery = Path(evidence["privateRecoveryDirectory"])
        self.addCleanup(lambda: __import__("shutil").rmtree(recovery, ignore_errors=True))
        self.assertTrue(recovery.is_dir())
        self.assertEqual(recovery.stat().st_mode & 0o777, 0o700)

    def test_wrong_container_owner_is_never_removed(self):
        environment = {**self.environment, "FAKE_OWNER_MISMATCH": "1"}
        result = self.invoke(environment=environment)
        self.assertEqual(result.returncode, 1)
        evidence = self.result()
        self.assertEqual(evidence["cleanup"], "not_confirmed")
        self.assertIn("refused to remove", evidence["failure"])
        self.assertTrue(self.state.exists())

    def test_missing_test_summaries_cannot_pass(self):
        environment = {**self.environment, "FAKE_CARGO_NO_SUMMARIES": "1"}
        result = self.invoke(environment=environment)
        self.assertEqual(result.returncode, 1)
        evidence = self.result()
        self.assertEqual(evidence["status"], "failed")
        self.assertIn("expected exactly 10", evidence["failure"])
        self.assertEqual(evidence["cleanup"], "confirmed")

    def test_owned_command_timeout_is_bounded(self):
        temporary = Path(tempfile.mkdtemp(prefix="ci-timeout-check-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        runner = ci.Runner(temporary)
        runner.temp_dir = temporary
        runner.log_path.touch()
        started = time.monotonic()
        code, _ = runner.run_command("sleeping-command", ["/bin/sh", "-c", "sleep 20"], timeout=0.2)
        self.assertEqual(code, 124)
        self.assertLess(time.monotonic() - started, 5)

    def test_sigterm_records_failure_and_cleans_owned_group_and_container(self):
        environment = {**self.environment, "FAKE_CARGO_SLEEP": "1"}
        process = subprocess.Popen(
            [sys.executable, str(RUNNER_PATH), "--output-dir", str(self.output)],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while not (self.root / "cargo-started").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertTrue((self.root / "cargo-started").exists(), "fake live test did not start")
        process.send_signal(__import__("signal").SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except BaseException:
            process.kill()
            process.communicate(timeout=5)
            raise
        self.assertEqual(process.returncode, 1, f"{stdout}\n{stderr}")
        evidence = self.result()
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["cleanup"], "confirmed")
        self.assertIn("interrupted", evidence["failure"])
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
