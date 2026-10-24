"""Run the existing acceptance suites in installed, headed macOS Chrome.

Each suite gets its own disposable fixture. Public evidence never includes the
private fixture, credentials or raw host logs. No images are pulled.
"""
import argparse
import datetime
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def redact(diagnostic, secrets):
    for secret in secrets:
        diagnostic = diagnostic.replace(secret, "[redacted]")
    for source, replacement in [(str(ROOT), "<repo>"), (str(Path.home()), "<home>"),
                                (str(Path(tempfile.gettempdir()).resolve()), "<tmp>")]:
        diagnostic = diagnostic.replace(source, replacement)
    return re.sub(r"data:text/javascript;base64,[A-Za-z0-9+/=]+", "data:text/javascript;base64,[source omitted]", diagnostic)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", required=True)
parser.add_argument("--playwright", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--suites", nargs="+", choices=["navigation", "clients", "authorization", "security", "console", "n1", "n2_mac"], required=True)
args = parser.parse_args()
chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
if not chrome.is_file() or not args.playwright.is_file():
    parser.error("Installed desktop Chrome and an existing Playwright module are required")
args.output.mkdir(parents=True, exist_ok=True)
failed = False
for suite in args.suites:
    out = args.output / suite
    # An existing directory may contain a failed attempt. Never overwrite it.
    out.mkdir(exist_ok=False)
    started = time.monotonic()
    record = {"suite": suite, "startedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "command": f"node scripts/check_management_{suite}.mjs", "headed": True,
              "browserExecutable": str(chrome), "freshFixture": True,
              "n2Layout": os.environ.get("IDP_UI_N2_LAYOUT") == "1"}
    state_path = None
    secrets = []
    try:
        prepare = ["python3", "scripts/prepare_management_navigation.py", "--image", args.image]
        if suite == "n2_mac":
            prepare.append("--isolated-cookies")
        prepared = subprocess.run(prepare,
                                  cwd=ROOT, text=True, capture_output=True, check=True)
        info = json.loads(prepared.stdout)
        state_path = info["fixture_file"]
        state = json.loads(Path(state_path).read_text())
        secrets = [state["password"], state["db_uri"]]
        record["postgresVersion"] = info["postgres_version"]
        record["origins"] = info["hosts"]
        env = {**os.environ, "IDP_UI_TEST_FIXTURE": state_path, "IDP_UI_PLAYWRIGHT_PATH": str(args.playwright.resolve()),
               "IDP_UI_BROWSER_EXECUTABLE": str(chrome), "IDP_UI_HEADED": "1", "IDP_UI_OUTPUT_DIR": str(out.resolve())}
        run = subprocess.run(["node", f"scripts/check_management_{suite}.mjs"], cwd=ROOT, env=env, text=True, capture_output=True)
        record["exitCode"] = run.returncode
        record["passLines"] = [line for line in run.stdout.splitlines() if line.startswith("PASS ")]
        # These suites print only test summaries/errors. Redact fixture secrets
        # defensively; full HAR/trace and host logs are deliberately excluded.
        record["diagnostic"] = redact(run.stderr, secrets)
        failed |= run.returncode != 0
    except subprocess.CalledProcessError as error:
        failed = True
        record["exitCode"] = error.returncode
        record["diagnostic"] = "Fixture preparation failed; private output not published"
    finally:
        if state_path:
            clean = subprocess.run(["python3", "scripts/prepare_management_navigation.py", "--cleanup", state_path],
                                   cwd=ROOT, capture_output=True, text=True)
            record["cleanup"] = {"exitCode": clean.returncode, "privateDirectoryRemoved": not Path(state_path).parent.exists()}
            failed |= clean.returncode != 0
        record["durationSeconds"] = round(time.monotonic() - started, 2)
        (out / "execution.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"suite": suite, "exitCode": record.get("exitCode"),
                          "passedGroups": len(record.get("passLines", [])), "cleanup": record.get("cleanup"),
                          "durationSeconds": record["durationSeconds"]}), flush=True)
raise SystemExit(1 if failed else 0)
