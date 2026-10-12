"""Build a pinned, checksummed release tarball for the NVR (run on a workstation).

    python3 -m shimlib.release --out dist                   from a clean working tree
    python3 -m shimlib.release --ref origin/main --out dist  from a commit, no checkout

The release directory name embeds the package version and the git commit, and
MANIFEST.sha256 lists every shipped file. Both forms produce identical tarballs
for the same commit. The NVR installer verifies the
manifest before switching to a release; nothing is downloaded on the NVR.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile

from . import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = (
    "onvif_shim.py",
    "shimctl.py",
    "install.sh",
    "uninstall.sh",
    "LICENSE",
    "README.md",
    "docs/architecture.md",
    "cameras.example.json",
    "examples/parking-east.json",
)
MANIFEST = "MANIFEST.sha256"


def git(root: str, *args: str, binary: bool = False):
    result = subprocess.run(["git", "-C", root, *args], capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise SystemExit(f"git {' '.join(args)}: {detail}")
    return result.stdout if binary else result.stdout.decode().strip()


def package_files(root: str = ROOT, ref: str | None = None) -> list[str]:
    """Shipped files, from the working tree or from the tree of git ref."""
    if ref is None:
        modules = sorted(
            f"shimlib/{name}"
            for name in os.listdir(os.path.join(root, "shimlib"))
            if name.endswith(".py")
        )
        return [f for f in FILES if os.path.exists(os.path.join(root, f))] + modules
    names = git(root, "ls-tree", "-r", "--name-only", ref, "--", *FILES, "shimlib").splitlines()
    modules = sorted(
        n for n in names if n.startswith("shimlib/") and n.count("/") == 1 and n.endswith(".py")
    )
    if "shimlib/__init__.py" not in modules:
        raise SystemExit(f"{ref} is not a multi-camera release (no shimlib/)")
    return [f for f in FILES if f in names] + modules


def git_version(root: str = ROOT, allow_dirty: bool = False, ref: str | None = None) -> str:
    if ref is not None:
        sha = git(root, "rev-parse", "--short=12", "--verify", f"{ref}^{{commit}}")
        package_files(root, ref)
        match = re.search(
            r'^__version__ = "([^"]+)"', git(root, "show", f"{ref}:shimlib/__init__.py"), re.M
        )
        if not match:
            raise SystemExit(f"{ref}: no __version__ in shimlib/__init__.py")
        return f"{match[1]}-g{sha}"
    sha = git(root, "rev-parse", "--short=12", "HEAD")
    dirty = bool(git(root, "status", "--porcelain", "--", *package_files(root)))
    if dirty and not allow_dirty:
        raise SystemExit("release files have uncommitted changes; commit first (pinning)")
    return f"{__version__}-g{sha}" + ("-dirty" if dirty else "")


def stage(dest: str, version: str, root: str = ROOT, ref: str | None = None) -> str:
    """Copy release files into dest/<version>/ with VERSION and MANIFEST.sha256."""
    target = os.path.join(dest, version)
    os.makedirs(target, exist_ok=False)
    lines = []
    for rel in package_files(root, ref) + ["VERSION"]:
        out = os.path.join(target, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if rel == "VERSION":
            data = (version + "\n").encode()
        elif ref is not None:
            data = git(root, "show", f"{ref}:{rel}", binary=True)
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
    parser.add_argument("--ref", help="build this commit (e.g. origin/main) without a checkout")
    args = parser.parse_args(argv)
    version = git_version(allow_dirty=args.allow_dirty, ref=args.ref)
    os.makedirs(args.out, exist_ok=True)
    staging = os.path.join(args.out, "staging")
    if os.path.exists(os.path.join(staging, version)):
        raise SystemExit(f"{staging}/{version} exists; remove it first")
    staged = stage(staging, version, ref=args.ref)
    path = tarball(staged, args.out)
    with open(path, "rb") as source:
        digest = hashlib.sha256(source.read()).hexdigest()
    print(f"release {version}\ntarball {path}\nsha256  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
