#!/usr/bin/env python3
"""Build the two local Linux arm64 artifacts for the bounded N2 batch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath


REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = Path("scripts/n2-linux/Dockerfile")
DOCKERIGNORE = Path("scripts/n2-linux/Dockerfile.dockerignore")
SCRIPT = Path("scripts/build_management_n2_linux.py")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$")
EXCLUDED_PARTS = {".git", ".local", "target", "node_modules", "dist", "docs"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def allowed(path: PurePosixPath) -> bool:
    if path.is_absolute() or ".." in path.parts or any(part in EXCLUDED_PARTS for part in path.parts):
        return False
    if any(part == ".env" or part.startswith(".env.") for part in path.parts):
        return False
    if path.as_posix() in {"Cargo.toml", "Cargo.lock"}:
        return True
    return (
        path.parts[0] in {"crates", "web"}
        or path.as_posix() == "examples/no-tenant-host/Cargo.toml"
        or path.as_posix().startswith("examples/no-tenant-host/src/")
        or (path.parts[0] == ".cargo" and len(path.parts) > 1)
    )


def tracked_sources() -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = PurePosixPath(raw.decode("utf-8", "strict"))
        if allowed(path):
            paths.append(path)
    return sorted(set(paths), key=lambda item: item.as_posix())


def copy_context(context: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    sources = tracked_sources()
    sources.extend([DOCKERFILE, DOCKERIGNORE, SCRIPT])
    for relative in sorted(set(sources), key=lambda item: item.as_posix()):
        if not allowed(relative) and relative not in {DOCKERFILE, DOCKERIGNORE, SCRIPT}:
            continue
        source = REPO.joinpath(*relative.parts)
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(f"required source is missing or not a regular file: {relative.as_posix()}")
        destination = context.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        entries.append({"path": relative.as_posix(), "sha256": sha256(destination)})

    required = {"Cargo.toml", "Cargo.lock", "crates/embedded-idp-app/Cargo.toml",
                "crates/embedded-idp-storage-postgres/Cargo.toml",
                "crates/embedded-idp-storage-postgres/examples/bootstrap_local_postgres.rs",
                "web/package.json", "web/pnpm-lock.yaml"}
    absent = required - {entry["path"] for entry in entries}
    if absent:
        raise RuntimeError("tracked build inputs are missing: " + ", ".join(sorted(absent)))
    return entries


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def redact(text: str, context: Path) -> str:
    replacements = [
        (str(context), "<BUILD_CONTEXT>"),
        (str(REPO), "<REPO>"),
        (str(Path.home()), "<HOME>"),
        ("/private/tmp", "<TMP>"),
        ("/tmp", "<TMP>"),
        ("/private/var/folders", "<TMP>"),
    ]
    for original, replacement in replacements:
        if original:
            text = text.replace(original, replacement)
    return text


def docker_environment() -> dict[str, str]:
    # Docker receives only connection/configuration variables, never app/database secrets.
    allowed = {"PATH", "HOME", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST"}
    return {key: os.environ[key] for key in allowed if key in os.environ}


def run_build(args: list[str], log: Path, context: Path) -> int:
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            args,
            cwd=context,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=docker_environment(),
        )
        assert process.stdout is not None
        for line in process.stdout:
            output.write(redact(line, context))
            output.flush()
        return process.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-image", required=True, help="frozen local Node image reference with sha256 digest")
    parser.add_argument("--rust-image", required=True, help="frozen local Rust image reference with sha256 digest")
    parser.add_argument("--runtime-image", required=True, help="frozen local Debian image reference with sha256 digest")
    parser.add_argument("--output", required=True, type=Path, help="new, non-existing directory for public evidence")
    options = parser.parse_args()

    image_refs = {
        "node": options.node_image,
        "rust": options.rust_image,
        "runtime": options.runtime_image,
    }
    invalid = [name for name, reference in image_refs.items() if not IMAGE_RE.fullmatch(reference)]
    if invalid:
        parser.error("each image must be a frozen image reference ending in @sha256:<64 lowercase hex digits>: " + ", ".join(invalid))

    output = options.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        parser.error("--output must name a directory that does not already exist")
    if not output.parent.is_dir():
        parser.error("--output parent directory must already exist")
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)

    try:
        with tempfile.TemporaryDirectory(prefix="idp-n2-linux-context-") as temporary:
            context = Path(temporary)
            manifest_entries = copy_context(context)
            manifest_material = "".join(f"{entry['path']}\0{entry['sha256']}\n" for entry in manifest_entries)
            source_id = hashlib.sha256(manifest_material.encode()).hexdigest()[:12]
            write_json(output / "source-manifest.json", {
                "schema": 1,
                "source_id": source_id,
                "git_head": subprocess.run(
                    ["git", "-C", str(REPO), "rev-parse", "HEAD"],
                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ).stdout.strip(),
                "files": manifest_entries,
            })

            for name, reference in image_refs.items():
                log = output / f"input-{name}-image.log"
                status = run_build(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
                    log,
                    context,
                )
                if status != 0:
                    write_json(output / "failure.json", {
                        "status": "blocked",
                        "stage": "verify-local-base-images",
                        "input": name,
                        "exit_code": status,
                        "detail": "frozen base image is not available locally; no pull was attempted",
                    })
                    return status or 1

            tags = {
                "runtime": f"idp-n2-linux:{source_id}-runtime",
                "prepare": f"idp-n2-linux:{source_id}-prepare",
            }
            for target, tag in tags.items():
                log = output / f"build-{target}.log"
                command = [
                    "docker", "buildx", "build", "--pull=false", "--platform", "linux/arm64",
                    "--load", "--progress=plain", "--file", DOCKERFILE.as_posix(),
                    "--build-arg", f"NODE_IMAGE={image_refs['node']}",
                    "--build-arg", f"RUST_IMAGE={image_refs['rust']}",
                    "--build-arg", f"RUNTIME_IMAGE={image_refs['runtime']}",
                    "--target", target, "--tag", tag, ".",
                ]
                status = run_build(command, log, context)
                if status != 0:
                    write_json(output / "failure.json", {
                        "status": "failed",
                        "stage": f"build-{target}",
                        "image": tag,
                        "exit_code": status,
                    })
                    return status or 1

            inspected = {}
            for target, tag in tags.items():
                result = subprocess.run(
                    ["docker", "image", "inspect", tag],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                image = json.loads(result.stdout)[0]
                inspected[target] = {
                    "name": tag,
                    "id": image.get("Id"),
                    "repo_digests": image.get("RepoDigests") or [],
                    "architecture": image.get("Architecture"),
                    "os": image.get("Os"),
                    "size_bytes": image.get("Size"),
                }
            write_json(output / "image-summary.json", {
                "status": "built-locally",
                "platform": "linux/arm64",
                "base_images": image_refs,
                "images": inspected,
                "registry_digest_note": "An empty RepoDigests list means no registry digest is available for this local build.",
            })
            return 0
    except Exception as error:  # retain a public, path-sanitized failure record
        safe_error = redact(str(error), Path("<BUILD_CONTEXT>"))
        write_json(output / "failure.json", {"status": "failed", "stage": "prepare-or-inspect", "error": safe_error})
        print(f"N2 Linux build preparation failed; evidence retained in {redact(str(output), Path('<BUILD_CONTEXT>'))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
