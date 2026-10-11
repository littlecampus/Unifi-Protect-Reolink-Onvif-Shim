"""Build a pinned, checksummed release tarball for the NVR (run on a workstation).

    python3 -m shimlib.release --out dist

The release directory name embeds the package version and the git commit, and
MANIFEST.sha256 lists every shipped file. The NVR installer verifies the
manifest before switching to a release; nothing is downloaded on the NVR.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile

from . import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = (
    "onvif_shim.py",
    "shimctl.py",
    "install.sh",
    "LICENSE",
    "README.md",
    "docs/architecture.md",
    "cameras.example.json",
    "examples/parking-east.json",
)
MANIFEST = "MANIFEST.sha256"


def package_files(root: str = ROOT) -> list[str]:
    modules = sorted(
        f"shimlib/{name}"
        for name in os.listdir(os.path.join(root, "shimlib"))
        if name.endswith(".py")
    )
    return [f for f in FILES if os.path.exists(os.path.join(root, f))] + modules


def git_version(root: str = ROOT, allow_dirty: bool = False) -> str:
    def git(*args):
        return subprocess.run(
            ["git", "-C", root, *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    sha = git("rev-parse", "--short=12", "HEAD")
    dirty = bool(git("status", "--porcelain", "--", *package_files(root)))
    if dirty and not allow_dirty:
        raise SystemExit("release files have uncommitted changes; commit first (pinning)")
    return f"{__version__}-g{sha}" + ("-dirty" if dirty else "")


def stage(dest: str, version: str, root: str = ROOT) -> str:
    """Copy release files into dest/<version>/ with VERSION and MANIFEST.sha256."""
    target = os.path.join(dest, version)
    os.makedirs(target, exist_ok=False)
    lines = []
    for rel in package_files(root) + ["VERSION"]:
        out = os.path.join(target, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if rel == "VERSION":
            data = (version + "\n").encode()
        else:
            with open(os.path.join(root, rel), "rb") as source:
                data = source.read()
        with open(out, "wb") as sink:
            sink.write(data)
        os.chmod(out, 0o755 if rel.endswith(("onvif_shim.py", "shimctl.py", ".sh")) else 0o644)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
    with open(os.path.join(target, MANIFEST), "w") as manifest:
        manifest.write("\n".join(lines) + "\n")
    return target


def tarball(staged: str, out_dir: str) -> str:
    """Deterministic tar.gz (root-owned entries, fixed mtimes)."""
    version = os.path.basename(staged)
    path = os.path.join(out_dir, f"onvif-shim-{version}.tar.gz")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for root, dirs, files in os.walk(staged):
            dirs.sort()
            for name in sorted(dirs) + sorted(files):
                full = os.path.join(root, name)
                info = tar.gettarinfo(full, arcname=os.path.relpath(full, os.path.dirname(staged)))
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                if info.isfile():
                    with open(full, "rb") as source:
                        tar.addfile(info, source)
                elif os.path.isdir(full):
                    tar.addfile(info)
    with open(path, "wb") as out, gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(buffer.getvalue())
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="dist")
    parser.add_argument("--allow-dirty", action="store_true", help="development only")
    args = parser.parse_args(argv)
    version = git_version(allow_dirty=args.allow_dirty)
    os.makedirs(args.out, exist_ok=True)
    staging = os.path.join(args.out, "staging")
    if os.path.exists(os.path.join(staging, version)):
        raise SystemExit(f"{staging}/{version} exists; remove it first")
    staged = stage(staging, version)
    path = tarball(staged, args.out)
    with open(path, "rb") as source:
        digest = hashlib.sha256(source.read()).hexdigest()
    print(f"release {version}\ntarball {path}\nsha256  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
