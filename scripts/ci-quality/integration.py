"""Owned, disposable Postgres runner for the repository's real integration suite."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_live_postgres_checks.sh"
sys.path.insert(0, str(ROOT / "scripts"))
from n2_ci_runtime import run_bounded


IMAGE = "postgres:18.6-bookworm"
OWNER_LABEL = "ci.integration.owner"
COMMAND_TIMEOUT_SECONDS = 18 * 60
STARTUP_TIMEOUT_SECONDS = 120
EXPECTED_TEST_TARGETS = {
    f"tests/{name}.rs" for name in (
        "live_postgres", "live_access", "live_access_admin", "live_access_bootstrap",
        "live_access_tenants", "live_business_admin", "live_pool", "live_tenant_registration",
        "live_bootstrap_admin", "live_reference_host",
    )
}
SUMMARY_PATTERN = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
    re.MULTILINE,
)


class RunInterrupted(Exception):
    """Distinct from OSError/EINTR, which subprocess may automatically retry."""


class Runner:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.started = datetime.now(timezone.utc)
        self.started_monotonic = time.monotonic()
        self.phase = "preflight"
        self.failure: str | None = None
        self.cleanup_confirmed = True
        self.command_records: list[dict] = []
        self.secret_values: list[str] = []
        self.temp_dir: Path | None = None
        self.log_path = output_dir / "integration.log"
        self.result_path = output_dir / "integration-result.json"
        self.owner = secrets.token_hex(12)
        self.container = f"idp-ci-pg-{self.owner}"
        self.uri = ""
        self.image_id: str | None = None
        self.source_sha: str | None = None
        self.runtime: dict[str, str | bool] = {}
        self.test_summaries: list[dict] = []
        self.cleaning_up = False
        self.command_groups_confirmed = True
        self.command_env = {**os.environ, "CARGO_TERM_COLOR": "never"}
        # Do not let a developer shell or CI secret override the disposable test target.
        for name in list(self.command_env):
            if name.startswith("EMBEDDED_IDP_") or name.startswith("PG"):
                self.command_env.pop(name, None)
        for name in ("IDP_UI_PROFILE", "IDP_N2_DEADLINE", "IDP_N2_PROCESS_REGISTRY"):
            self.command_env.pop(name, None)
            os.environ.pop(name, None)

    def run_command(self, label: str, command: list[str], *, timeout: float = COMMAND_TIMEOUT_SECONDS,
                    env: dict[str, str] | None = None) -> tuple[int, str]:
        """Run one bounded command and retain credential-redacted diagnostics."""
        started = time.monotonic()
        try:
            result = run_bounded(command, cwd=ROOT, env=env or self.command_env, timeout=timeout, stderr=subprocess.STDOUT)
            code = result.returncode
            content = (result.stdout or "") + (result.stderr or "")
        except RunInterrupted as error:
            self._record_command(label, 130, self._partial_output(error), started)
            raise
        except subprocess.TimeoutExpired as error:
            code = 124
            content = self._partial_output(error)
            content += "\ncommand timed out; owned process group was terminated\n"
        except OSError as error:
            code = 127
            content = f"command could not start: {type(error).__name__}\n"
        except RuntimeError as error:
            self.command_groups_confirmed = False
            self.fail("cleanup could not confirm termination of an owned command process group")
            self._record_command(label, 1, self._partial_output(error), started)
            raise
        return self._record_command(label, code, content, started)

    @staticmethod
    def _partial_output(error: BaseException) -> str:
        output = getattr(error, "stdout", None) or getattr(error, "output", None) or ""
        if isinstance(output, bytes):
            return output.decode("utf-8", errors="replace")
        return output

    def _record_command(self, label: str, code: int, content: str, started: float) -> tuple[int, str]:
        for secret in sorted(self.secret_values, key=len, reverse=True):
            if secret:
                content = content.replace(secret, "[REDACTED]")
        duration = round(time.monotonic() - started, 3)
        with self.log_path.open("a", encoding="utf-8") as log:
            log.write(f"\n--- {label}: exit {code}, {duration:.3f}s ---\n")
            log.write(content)
            if content and not content.endswith("\n"):
                log.write("\n")
        self.command_records.append({"name": label, "exitCode": code, "durationSeconds": duration})
        return code, content

    def fail(self, message: str) -> None:
        if self.failure is None:
            self.failure = message

    def dependencies(self) -> list[str]:
        required = ["docker", "pnpm", "cargo", "rustc", "node", "git"]
        return [name for name in required if shutil.which(name) is None]

    def create_private_inputs(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="idp-ci-integration-"))
        os.chmod(self.temp_dir, 0o700)
        (self.temp_dir / "ownership.json").write_text(
            json.dumps({"container": self.container, "ownerLabel": OWNER_LABEL, "owner": self.owner}),
            encoding="utf-8",
        )
        (self.temp_dir / "ownership.json").chmod(0o600)
        password = secrets.token_hex(24)
        self.secret_values = [password]
        env_file = self.temp_dir / "postgres.env"
        env_file.write_text(
            "POSTGRES_USER=ci_integration\n"
            f"POSTGRES_PASSWORD={password}\n"
            "POSTGRES_DB=ci_integration\n",
            encoding="utf-8",
        )
        env_file.chmod(0o600)
        common = self.temp_dir / "common.env"
        common.write_text(
            "EMBEDDED_IDP_APP_TENANCY_MODE=disabled\n"
            "EMBEDDED_IDP_APP_PG_SCHEMA=embedded_idp_disabled_v2\n",
            encoding="utf-8",
        )
        common.chmod(0o600)
        mode = self.temp_dir / "mode.env"
        mode.write_text(
            "EMBEDDED_IDP_APP_TENANCY_MODE=disabled\n"
            "EMBEDDED_IDP_APP_PG_SCHEMA=embedded_idp_disabled_v2\n",
            encoding="utf-8",
        )
        mode.chmod(0o600)
        self.command_env.update({
            "EMBEDDED_IDP_COMMON_ENV_FILE": str(common),
            "EMBEDDED_IDP_APP_ENV_FILE": str(mode),
        })

    def inspect_labels(self) -> tuple[int, dict]:
        code, output = self.run_command(
            "inspect-container-owner",
            ["docker", "inspect", "--format={{json .Config.Labels}}", self.container],
            timeout=15,
        )
        if code != 0:
            return code, {}
        try:
            labels = json.loads(output.strip())
        except (json.JSONDecodeError, TypeError):
            return 1, {}
        return 0, labels if isinstance(labels, dict) else {}

    def cleanup(self) -> None:
        # The exact generated name is filtered first; removal is allowed only after label readback.
        code, output = self.run_command(
            "check-owned-container",
            ["docker", "ps", "-a", "--filter", f"name={self.container}", "--format={{.Names}}"],
            timeout=15,
        )
        if code != 0:
            self.cleanup_confirmed = False
            self.fail("cleanup could not confirm the owned container state")
            return
        names = [line for line in output.splitlines() if line]
        if not names:
            self.cleanup_confirmed = True
            return
        if names != [self.container]:
            self.cleanup_confirmed = False
            self.fail("cleanup found an unexpected container name")
            return
        inspect_code, labels = self.inspect_labels()
        if inspect_code != 0 or labels.get(OWNER_LABEL) != self.owner:
            self.cleanup_confirmed = False
            self.fail("cleanup refused to remove a container without matching ownership")
            return
        remove_code, _ = self.run_command(
            "remove-owned-container",
            ["docker", "rm", "--force", "--volumes", self.container],
            timeout=30,
        )
        if remove_code != 0:
            self.cleanup_confirmed = False
            self.fail("cleanup failed to remove the owned Postgres container")
            return
        verify_code, verify_output = self.run_command(
            "verify-container-removed",
            ["docker", "ps", "-a", "--filter", f"name={self.container}", "--format={{.Names}}"],
            timeout=15,
        )
        self.cleanup_confirmed = verify_code == 0 and not verify_output.strip()
        if not self.cleanup_confirmed:
            self.fail("cleanup could not confirm removal of the owned Postgres container")

    def readiness(self) -> str | None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            code, _ = self.run_command(
                "postgres-readiness-probe",
                ["docker", "exec", self.container, "pg_isready", "-h", "127.0.0.1", "-q",
                 "-U", "ci_integration", "-d", "ci_integration"],
                timeout=5,
            )
            if code == 0:
                return None
            time.sleep(1)
        return "Postgres did not become ready before the 120-second deadline"

    def start_database(self) -> str | None:
        self.phase = "postgres_start"
        code, output = self.run_command(
            "verify-postgres-image",
            ["docker", "image", "inspect", "--format={{.Id}}", IMAGE],
            timeout=30,
        )
        if code != 0 or not output.strip():
            return "the pinned Postgres image must be available locally before integration starts"
        self.image_id = output.strip().splitlines()[0]
        env_file = self.temp_dir / "postgres.env"
        code, _ = self.run_command(
            "start-owned-postgres",
            ["docker", "run", "--pull=never", "--detach", "--name", self.container,
             "--label", f"{OWNER_LABEL}={self.owner}",
             "--publish", "127.0.0.1::5432", "--env-file", str(env_file), IMAGE],
            timeout=180,
        )
        if code != 0:
            return f"could not start the disposable Postgres container (exit {code})"
        code, output = self.run_command(
            "read-postgres-port",
            ["docker", "port", self.container, "5432/tcp"],
            timeout=15,
        )
        if code != 0:
            return "could not read the host port assigned to Postgres"
        match = re.fullmatch(r"127\.0\.0\.1:(\d+)\s*", output.strip())
        if not match:
            return "Docker did not report a loopback-only Postgres port"
        self.phase = "postgres_readiness"
        problem = self.readiness()
        if problem:
            return problem
        password = (self.temp_dir / "postgres.env").read_text(encoding="utf-8")
        password_match = re.search(r"^POSTGRES_PASSWORD=(.+)$", password, re.MULTILINE)
        if not password_match:
            return "private Postgres credentials are incomplete"
        secret = password_match.group(1)
        self.uri = f"postgres://ci_integration:{secret}@127.0.0.1:{match.group(1)}/ci_integration"
        self.secret_values.append(self.uri)
        self.command_env["EMBEDDED_IDP_TEST_PG_CONNECTION_URI"] = self.uri
        code, output = self.run_command(
            "read-postgres-version",
            ["docker", "exec", self.container, "postgres", "--version"],
            timeout=15,
        )
        if code != 0 or not output.strip():
            return "could not record the Postgres server version"
        self.runtime["postgres"] = output.strip()
        return None

    def collect_runtime(self) -> str | None:
        self.phase = "runtime_inventory"
        commands = {
            "sourceSha": ["git", "rev-parse", "HEAD"],
            "workingTree": ["git", "status", "--porcelain", "--untracked-files=normal"],
            "rust": ["rustc", "--version"],
            "node": ["node", "--version"],
            "pnpm": ["pnpm", "--version"],
        }
        for name, command in commands.items():
            code, output = self.run_command(f"record-{name}", command, timeout=20)
            if code != 0 or (name != "workingTree" and not output.strip()):
                return f"could not record runtime value: {name}"
            value = output.strip().splitlines()[0] if output.strip() else ""
            if name == "sourceSha":
                self.source_sha = value
            elif name == "workingTree":
                self.runtime["workingTreeDirty"] = bool(output.strip())
            else:
                self.runtime[name] = value
        self.runtime["system"] = f"{platform.system()} {platform.release()}"
        self.runtime["architecture"] = platform.machine()
        return None

    def parse_test_summaries(self, output: str) -> list[dict]:
        target_pattern = re.compile(r"^\s*Running\s+(.+?)\s+\([^)]+\)$", re.MULTILINE)
        targets = list(target_pattern.finditer(output))
        summaries = []
        for index, match in enumerate(SUMMARY_PATTERN.finditer(output), start=1):
            preceding = [target for target in targets if target.start() < match.start()]
            if preceding:
                parts = Path(preceding[-1].group(1).strip()).parts
                target = "tests/" + "/".join(parts[parts.index("tests") + 1:]) if "tests" in parts else parts[-1]
            else:
                target = f"live-test-target-{index}"
            summaries.append({
                "target": target,
                "status": match.group(1),
                "passed": int(match.group(2)),
                "failed": int(match.group(3)),
                "ignored": int(match.group(4)),
            })
        return summaries

    def execute(self) -> int:
        output_dir_ready = False
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.output_dir, 0o700)
            if any(self.output_dir.iterdir()):
                print(f"output directory must be empty: {self.output_dir}", file=sys.stderr)
                return 2
            self.log_path.touch(mode=0o600)
            output_dir_ready = True
            missing = self.dependencies()
            if missing:
                self.fail("missing required command(s): " + ", ".join(missing))
            else:
                self.create_private_inputs()
                issue = self.collect_runtime()
                if issue:
                    self.fail(issue)
            if self.failure is None:
                issue = self.start_database()
                if issue:
                    self.fail(issue)
                else:
                    self.phase = "live_postgres_checks"
                    code, test_output = self.run_command(
                        "existing-live-postgres-checks",
                        [str(SCRIPT), "disabled"],
                        timeout=COMMAND_TIMEOUT_SECONDS,
                    )
                    self.test_summaries = self.parse_test_summaries(test_output)
                    if code != 0:
                        self.fail(f"existing live Postgres checks failed (exit {code})")
                        self.run_command("private-postgres-failure-diagnostic",
                                         ["docker", "logs", "--tail", "150", self.container], timeout=15)
                    elif (len(self.test_summaries) != len(EXPECTED_TEST_TARGETS)
                          or {item["target"] for item in self.test_summaries} != EXPECTED_TEST_TARGETS):
                        self.fail("expected exactly 10 distinct live test targets")
                    elif any(item["status"] != "ok" or item["passed"] <= 0 or item["failed"] or item["ignored"]
                             for item in self.test_summaries):
                        self.fail("one or more live test targets had failures, no passes, or ignored cases")
                    else:
                        self.phase = "complete"
        except Exception as error:  # Keep artifact and ownership cleanup on every unexpected failure.
            self.fail(f"runner error: {type(error).__name__}")
        finally:
            self.cleaning_up = True
            try:
                if self.temp_dir is not None:
                    self.cleanup()
                    if not self.command_groups_confirmed:
                        self.cleanup_confirmed = False
                    if self.cleanup_confirmed:
                        shutil.rmtree(self.temp_dir, ignore_errors=True)
                        if self.temp_dir.exists():
                            self.cleanup_confirmed = False
                            self.fail("cleanup could not remove the private temporary directory")
            except BaseException as error:
                self.cleanup_confirmed = False
                self.fail(f"cleanup error: {type(error).__name__}")
            finally:
                if output_dir_ready:
                    self.write_result()

        print(f"CI integration: {'passed' if self.failure is None else 'failed'}")
        print(f"Evidence: {self.result_path}")
        if self.failure:
            print(f"Failure: {self.failure}", file=sys.stderr)
            print(f"Private diagnostic log: {self.log_path}", file=sys.stderr)
            return 1
        return 0

    def write_result(self) -> None:
        finished = datetime.now(timezone.utc)
        result = {
            "schemaVersion": 1,
            "status": "passed" if self.failure is None else "failed",
            "phase": self.phase,
            "startedAt": self.started.isoformat(),
            "finishedAt": finished.isoformat(),
            "durationSeconds": round(time.monotonic() - self.started_monotonic, 3),
            "postgresImage": IMAGE,
            "postgresImageId": self.image_id,
            "sourceSha": self.source_sha,
            "runtime": self.runtime,
            "testTargets": self.test_summaries,
            "checks": self.command_records,
            "cleanup": "confirmed" if self.cleanup_confirmed else "not_confirmed",
            "ownedCommandGroups": "confirmed" if self.command_groups_confirmed else "not_confirmed",
            "failure": self.failure,
            "log": self.log_path.name,
            "privateRecoveryDirectory": str(self.temp_dir) if self.temp_dir and self.temp_dir.exists() else None,
        }
        self.result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        self.result_path.chmod(0o600)


def default_output() -> Path:
    suffix = secrets.token_hex(4)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(tempfile.gettempdir()) / f"idp-ci-integration-result-{stamp}-{suffix}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the real Postgres integration suite in an owned Docker container.")
    parser.add_argument("--output-dir", type=Path, help="new or empty directory for public result JSON and private diagnostic log")
    arguments = parser.parse_args(argv)
    output_dir = (arguments.output_dir or default_output()).expanduser().absolute()
    runner = Runner(output_dir)
    def handle_signal(signum, _frame):
        runner.fail(f"runner interrupted by signal {signum}")
        if not runner.cleaning_up:
            raise RunInterrupted("CI integration runner interrupted")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    return runner.execute()


if __name__ == "__main__":
    raise SystemExit(main())
