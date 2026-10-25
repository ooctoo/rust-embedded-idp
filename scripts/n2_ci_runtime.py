"""Bounded, owned subprocesses for the N2 CI tooling (no product dependencies)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import time


def ci_profile() -> bool:
    return os.environ.get("IDP_UI_PROFILE") == "ci-functional"


def command_timeout(default: float = 30) -> float:
    deadline = os.environ.get("IDP_N2_DEADLINE")
    remaining = float(deadline) - time.monotonic() if deadline else default
    if remaining <= 0:
        raise TimeoutError("N2 command deadline exceeded")
    return min(default, remaining)


def process_record(pid: int) -> dict | None:
    """Read numeric ancestry/identity only; never inspect process arguments or secrets."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if not fields or fields[0] not in {"R", "S", "D", "Z", "T", "t", "W", "X", "x", "K", "P", "I"}:
            raise ValueError("invalid process state")
        if fields[0] in ("Z", "X"):
            return None  # A zombie cannot run or retain a browser profile.
        ppid, pgid = int(fields[1]), int(fields[2])
        start_ticks = fields[19]
        if not start_ticks.isdecimal():
            raise ValueError("invalid process start time")
        return {"pid": pid, "ppid": ppid, "pgid": pgid, "startTicks": start_ticks}
    except (FileNotFoundError, ProcessLookupError):
        return None
    except (OSError, IndexError, ValueError) as error:
        if ci_profile():
            raise RuntimeError(f"CI process record unavailable for pid {pid}: {type(error).__name__}") from None
        return None


def process_identity(pid: int) -> str | None:
    """Linux start ticks prevent a later cleanup from signalling a reused PID."""
    record = process_record(pid)
    return record["startTicks"] if record else None


def process_snapshot() -> dict[int, dict]:
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        if ci_profile():
            raise RuntimeError("CI process inventory is unavailable") from None
        return {}
    records = (process_record(int(entry.name)) for entry in entries if entry.name.isdecimal())
    return {record["pid"]: record for record in records if record}


def register_identity(record: dict) -> None:
    registry = os.environ.get("IDP_N2_PROCESS_REGISTRY")
    if not registry:
        return
    with os.fdopen(os.open(registry, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a") as stream:
        stream.write(json.dumps(record) + "\n")


def track_descendants(root: dict, tracked: dict[int, dict]) -> None:
    """Follow only roots with the captured start ticks, including detached sessions."""
    snapshot = process_snapshot()
    owned = {record["pid"] for record in [root, *tracked.values()]
             if record["startTicks"] is not None and
             snapshot.get(record["pid"], {}).get("startTicks") == record["startTicks"]}
    pending = list(snapshot.values())
    changed = True
    while changed:
        changed = False
        for record in pending:
            pid = record["pid"]
            if pid == root["pid"] or pid in owned or record["ppid"] not in owned:
                continue
            # Do not overwrite a previously observed PID that has since been reused.
            # A reused PID is a new owned child only when its current parent is owned.
            tracked[pid] = record
            register_identity({key: record[key] for key in ("pid", "pgid", "startTicks")})
            owned.add(pid)
            changed = True


def live_descendants(tracked: dict[int, dict]) -> list[dict]:
    return [record for record in tracked.values()
            if process_identity(record["pid"]) == record["startTicks"]]


def stop_descendants(tracked: dict[int, dict], grace: float = 2) -> None:
    """Signal exact observed descendants even when they started a new session."""
    errors = []
    for signum, wait in [(signal.SIGTERM, grace), (signal.SIGKILL, 1)]:
        for record in live_descendants(tracked):
            try:
                os.kill(record["pid"], signum)
            except ProcessLookupError:
                pass
            except OSError as error:
                errors.append(type(error).__name__)
        end = time.monotonic() + wait
        while live_descendants(tracked) and time.monotonic() < end:
            time.sleep(.02)
        if not live_descendants(tracked):
            return
    if live_descendants(tracked):
        raise RuntimeError("Owned descendant exit could not be confirmed" +
                           (": " + ",".join(sorted(set(errors))) if errors else ""))


def stop_process_group(process: subprocess.Popen, grace: float = 2, identity: str | None = None) -> None:
    """Signal only the session created for this exact subprocess, including children."""
    if identity is None:
        # Popen gives us the direct-child PID. While that child still exists
        # (including as an unreaped zombie), its PID cannot have been reused,
        # so its freshly-created session can be killed safely without procfs.
        try:
            os.kill(process.pid, 0)
        except ProcessLookupError:
            process.wait(timeout=grace)
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            raise RuntimeError("Owned process group identity cannot be established")
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=grace)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        raise RuntimeError("Owned subprocess group exit could not be confirmed")
    for signum, wait in [(signal.SIGTERM, grace), (signal.SIGKILL, 1)]:
        current = process_identity(process.pid)
        if current is not None and current != identity:
            raise RuntimeError("Owned process group identity changed")
        if current is None:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                process.wait(timeout=wait)
                return
            raise RuntimeError("Owned process group leader exit cannot establish group ownership")
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            process.wait(timeout=wait)
            return
        try:
            process.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            continue
        # The parent may have exited while its Chromium child remains alive.
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return
    raise RuntimeError("Owned subprocess group exit could not be confirmed")


def run_bounded(args, *, input=None, text=True, capture_output=True, check=False,
                timeout=30, cwd=None, env=None, **kwargs):
    """subprocess.run equivalent with a deadline and descendant cleanup on interruption."""
    if not text or not capture_output:
        raise ValueError("N2 subprocesses require captured text output")
    limit = command_timeout(timeout)
    stderr_target = kwargs.pop("stderr", subprocess.PIPE)
    process = subprocess.Popen(args, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=stderr_target, text=True,
                               cwd=cwd, env=env, start_new_session=True, **kwargs)
    tracked = {}
    root = {"pid": process.pid, "startTicks": None}
    cleanup_started = False

    def cleanup():
        nonlocal cleanup_started
        cleanup_started = True
        failures = []
        try:
            track_descendants(root, tracked)
            stop_descendants(tracked)
        except BaseException as error:
            failures.append(type(error).__name__)
        try:
            stop_process_group(process, identity=root["startTicks"])
        except BaseException as error:
            failures.append(type(error).__name__)
        if failures:
            raise RuntimeError("Owned subprocess cleanup failed: " + ",".join(failures))

    try:
        # Arm cleanup before procfs identity lookup: an unreadable record must
        # not strand the process that was just spawned.
        root["startTicks"] = process_identity(process.pid)
        register_identity({**root, "pgid": process.pid})
        end = time.monotonic() + limit
        first = True
        last_timeout = None
        while True:
            track_descendants(root, tracked)
            remaining = end - time.monotonic()
            if remaining <= 0:
                if last_timeout is not None:
                    last_timeout.timeout = limit
                    raise last_timeout
                raise subprocess.TimeoutExpired(args, limit)
            try:
                stdout, stderr = process.communicate(input=input if first else None,
                                                     timeout=min(.1, remaining))
                break
            except subprocess.TimeoutExpired as error:
                last_timeout = error
                if time.monotonic() >= end:
                    error.timeout = limit
                    raise
            finally:
                first = False
        # Capture children still parented to an observed descendant after Node exit.
        track_descendants(root, tracked)
    except BaseException:
        if not cleanup_started:
            cleanup()
        raise
    # A checker must not report success while owned children or its session remain.
    try:
        orphaned = bool(live_descendants(tracked))
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            group_alive = False
        else:
            group_alive = True
    except BaseException:
        cleanup()
        raise
    if orphaned or group_alive:
        cleanup()
        raise RuntimeError("Subprocess left owned descendants running")
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr or "")
    if check:
        result.check_returncode()
    return result
