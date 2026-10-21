"""Disposable UI-B browser fixtures. Never reads repository .env files.

Build the Web app, embedded-idp-app and bootstrap_local_postgres example first.
Pass --image for an installed PostgreSQL 18 image; no image is pulled. The
returned state.json is owner-only and contains disposable test credentials.
"""
import argparse
import base64
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
BINARY = ROOT / "target/debug/embedded-idp-app"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", help="explicit installed PostgreSQL 18 image")
parser.add_argument("--cleanup", type=pathlib.Path, help="private state.json returned by this script")
args = parser.parse_args()


def cleanup(file):
    file = file.resolve()
    state = json.loads(file.read_text())
    directory = file.parent
    if (not directory.name.startswith("idp-ui-b-") or
            directory.parent != pathlib.Path(tempfile.gettempdir()).resolve() or
            pathlib.Path(state["dir"]).resolve() != directory or
            not re.fullmatch(r"idp-ui-b-[a-f0-9]+", state["container"])):
        raise ValueError("Not an owned disposable UI-B fixture")
    label = subprocess.check_output([
        "docker", "inspect", "--format", '{{index .Config.Labels "idp.ui-b.fixture"}}', state["container"]
    ], text=True).strip()
    if label != str(directory):
        raise ValueError("Container fixture ownership label does not match")
    for host in state["hosts"].values():
        config = pathlib.Path(host["config"]).resolve()
        if config.parent != directory:
            raise ValueError("Host configuration is outside the fixture directory")
        command = subprocess.run(["ps", "-p", str(host["pid"]), "-o", "command="], capture_output=True, text=True).stdout
        if not command:
            continue
        if str(BINARY) not in command or str(config) not in command:
            raise ValueError("Host PID has been reused; refusing to terminate it")
        os.kill(host["pid"], signal.SIGTERM)
    subprocess.run(["docker", "rm", "-f", "-v", state["container"]], check=True, stdout=subprocess.DEVNULL)
    shutil.rmtree(directory)
    print("Removed disposable UI-B hosts, container and private fixture files")


if args.cleanup:
    cleanup(args.cleanup)
    raise SystemExit()
if not args.image:
    parser.error("--image is required when preparing fixtures")
subprocess.run(["docker", "image", "inspect", args.image], check=True, stdout=subprocess.DEVNULL)
os.umask(0o077)
directory = pathlib.Path(tempfile.mkdtemp(prefix="idp-ui-b-")).resolve()
container = "idp-ui-b-" + uuid.uuid4().hex[:10]
password = "UiB-" + uuid.uuid4().hex + "aA!"
db_password = uuid.uuid4().hex
clean_env = {key: value for key, value in os.environ.items() if not key.startswith("EMBEDDED_IDP_")}
children = []


def run(command, env=None, input=None):
    result = subprocess.run(command, cwd=ROOT, env=env or clean_env, input=input, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError("Fixture command failed: " + command[0] + "; " + result.stderr[-600:])
    return result.stdout.strip()


def start(mode, schema, label, policy, mount="/identity", ui="/console"):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = "http://127.0.0.1:" + str(port)
    config = {
        "version": 1,
        "runtime": {"tenancy_mode": mode, "bind_addr": "127.0.0.1:" + str(port), "issuer": origin,
                    "signing_key_file": "key.der", "postgres": {"connection": {
                        "uri_ref": {"env": "UI_B_DATABASE_URI"}, "schema_name": schema, "tls_mode": "disable"}},
                    "http": {"browser_origin": origin}},
        "management": {"login_entry": label, "client_id": "management-ui-b", "tenant_policy": policy,
                       "mount_prefix": mount, "browser": {"cookie_name": "idp_ui_b"}, "ui": {"base_path": ui}},
        "business_entries": [],
    }
    file = directory / (label + ".json")
    file.write_text(json.dumps(config))
    with (directory / (label + ".log")).open("w") as log:
        child = subprocess.Popen([str(BINARY), "--config", str(file)], cwd=directory,
                                 env={**clean_env, "UI_B_DATABASE_URI": uri}, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=log, start_new_session=True)
    children.append(child)
    for _ in range(200):
        if child.poll() is not None:
            raise RuntimeError("Host exited: " + label + "; see private fixture log")
        try:
            with urllib.request.urlopen(origin + "/readyz", timeout=.5):
                return {"mode": mode, "label": label, "origin": origin, "mount": mount, "ui": ui,
                        "pid": child.pid, "config": str(file)}
        except (OSError, urllib.error.URLError):
            time.sleep(.1)
    raise RuntimeError("Host readiness timeout: " + label)


def api(host, path, method="GET", data=None, token=None, target=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if target:
        headers["X-Embedded-Idp-Tenant-Id"] = target
    request = urllib.request.Request(host["origin"] + host["mount"] + "/admin" + path,
                                     data=None if data is None else json.dumps(data).encode(),
                                     headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response) if response.status != 204 else None


try:
    env_file = directory / "postgres.env"
    env_file.write_text("POSTGRES_USER=uib\nPOSTGRES_DB=uib\nPOSTGRES_PASSWORD=" + db_password + "\n")
    run(["docker", "run", "--pull=never", "-d", "--name", container, "--label", "idp.ui-b.fixture=" + str(directory),
         "--env-file", str(env_file), "-p", "127.0.0.1::5432", args.image])
    for _ in range(100):
        # The image's temporary initialization server accepts Unix sockets before
        # CREATE DATABASE. Wait for the final TCP listener instead.
        if subprocess.run(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "uib", "-d", "uib"], capture_output=True).returncode == 0:
            break
        time.sleep(.2)
    version = run(["docker", "exec", container, "psql", "-At", "-U", "uib", "-d", "uib", "-c", "show server_version"])
    if not version.startswith("18."):
        raise ValueError("PostgreSQL 18 fixture required")
    port = json.loads(run(["docker", "inspect", container]))[0]["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
    uri = "postgresql://uib:" + db_password + "@127.0.0.1:" + port + "/uib"
    (directory / "key.der").write_bytes(base64.b64decode((ROOT / "crates/embedded-idp-security/tests/fixtures/rsa_3072_key_1.pk8.b64").read_text()))
    hosts, schemas = {}, {}
    for mode in ["enabled", "disabled"]:
        schema = "uib_" + mode + "_" + uuid.uuid4().hex[:10]
        schemas[mode] = schema
        env = {**clean_env, "EMBEDDED_IDP_APP_PG_URI": uri, "EMBEDDED_IDP_APP_PG_SCHEMA": schema,
               "EMBEDDED_IDP_APP_PG_TLS_MODE": "disable", "EMBEDDED_IDP_APP_TENANCY_MODE": mode}
        run([str(ROOT / "target/debug/examples/bootstrap_local_postgres"), "--access-schema"], env)
        run([str(BINARY), "bootstrap-admin", "--email", "admin@example.test", "--password-stdin"], env, password + "\n")
        sql = (f"insert into {schema}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) "
               "values ('management-ui-b','UI B management','[\"http://127.0.0.1/callback\"]','public_desktop',true,1);")
        run(["docker", "exec", "-i", container, "psql", "-v", "ON_ERROR_STOP=1", "-U", "uib", "-d", "uib"], input=sql)
        hosts[mode] = start(mode, schema, mode, {"kind": "fixed", "tenant_id": "0"},
                            mount="/identity" if mode == "enabled" else "/gateway", ui="/console" if mode == "enabled" else "/manage")
    enabled = hosts["enabled"]
    token = api(enabled, "/auth/login", "POST", {"email": "admin@example.test", "password": password})["tokens"]["access_token"]
    for tenant in ["tenant-a", "tenant-b", ".", ".."]:
        api(enabled, "/tenants", "POST", {"tenant_id": tenant, "name": "UI B " + tenant, "allow_registration": False,
                                          "administrator": {"kind": "new", "email": {".": "dot@example.test", "..": "dotdot@example.test"}.get(tenant, tenant + "@example.test"), "password": password}}, token)
    subject = api(enabled, "/accounts", token=token, target="tenant-a")["items"][0]["account_id"]
    api(enabled, "/members/" + subject + "/bind", "POST", {}, token, "tenant-b")
    api(enabled, "/access/security-admins/" + subject, "POST", None, token, "tenant-b")
    for tenant in [".", ".."]:
        api(enabled, "/members/" + subject + "/bind", "POST", {}, token, tenant)
        api(enabled, "/access/security-admins/" + subject, "POST", None, token, tenant)
    hosts["fixed"] = start("enabled", schemas["enabled"], "fixed", {"kind": "fixed", "tenant_id": "tenant-a"})
    hosts["choose"] = start("enabled", schemas["enabled"], "choose", {"kind": "choose"})
    state = {"dir": str(directory), "container": container, "db_uri": uri, "password": password,
             "hosts": hosts, "schemas": schemas, "pg_version": version}
    (directory / "state.json").write_text(json.dumps(state))
    print(json.dumps({"fixture_file": str(directory / "state.json"), "postgres_version": version,
                      "hosts": {key: host["origin"] + host["ui"] + "/" for key, host in hosts.items()}}))
except BaseException:
    for child in children:
        child.terminate()
        child.wait(timeout=10)
    subprocess.run(["docker", "rm", "-f", "-v", container], capture_output=True)
    shutil.rmtree(directory)
    raise
