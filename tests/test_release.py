"""Release builds from the working tree and from a git ref (no checkout)."""

import hashlib
import os
import subprocess

import pytest

from shimlib import release


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    write(root, "shimlib/__init__.py", '__version__ = "9.9.9"\n')
    write(root, "shimlib/a.py", "A = 1\n")
    for name in ("onvif_shim.py", "shimctl.py", "install.sh", "LICENSE"):
        write(root, name, f"# {name}\n")
    write(root, "notes.md", "not shipped\n")
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-qm", "base")
    return root


def sha256(path):
    with open(path, "rb") as source:
        return hashlib.sha256(source.read()).hexdigest()


def test_ref_build_uses_committed_files_and_ignores_the_working_tree(repo, tmp_path):
    write(repo, "shimlib/a.py", "A = 2  # uncommitted\n")
    write(repo, "shimlib/b.py", "B = 1  # untracked\n")
    write(repo, "shimlib/__init__.py", '__version__ = "10.0.0"\n')
    with pytest.raises(SystemExit, match="uncommitted"):
        release.git_version(str(repo))
    head = git(repo, "rev-parse", "--short=12", "HEAD")
    version = release.git_version(str(repo), ref="HEAD")
    assert version == f"9.9.9-g{head}"
    staged = release.stage(str(tmp_path / "out"), version, str(repo), ref="HEAD")
    with open(os.path.join(staged, "shimlib", "a.py")) as source:
        assert source.read() == "A = 1\n"
    assert not os.path.exists(os.path.join(staged, "shimlib", "b.py"))
    assert not os.path.exists(os.path.join(staged, "notes.md"))
    with open(os.path.join(staged, release.MANIFEST)) as source:
        listed = sorted(line.split("  ")[1] for line in source.read().splitlines())
    assert listed == sorted(
        [
            "LICENSE",
            "VERSION",
            "install.sh",
            "onvif_shim.py",
            "shimctl.py",
            "shimlib/__init__.py",
            "shimlib/a.py",
        ]
    )


def test_ref_build_matches_a_clean_checkout_build(repo, tmp_path):
    release.git_version(str(repo))  # clean tree: the working-tree build is allowed
    version = release.git_version(str(repo), ref="HEAD")
    from_ref = release.tarball(
        release.stage(str(tmp_path / "s1"), version, str(repo), ref="HEAD"),
        str(tmp_path),
    )
    clean = tmp_path / "clean"
    os.makedirs(clean)
    from_tree = release.tarball(
        release.stage(str(tmp_path / "s2"), version, str(repo)),
        str(clean),
    )
    assert sha256(from_ref) == sha256(from_tree)


def test_ref_must_exist_and_contain_the_multi_camera_shim(repo):
    with pytest.raises(SystemExit, match="no-such-ref"):
        release.git_version(str(repo), ref="no-such-ref")
    git(repo, "checkout", "-q", "--orphan", "v1")
    git(repo, "rm", "-rqf", "shimlib")
    git(repo, "commit", "-qm", "single-camera v1")
    with pytest.raises(SystemExit, match="not a multi-camera release"):
        release.git_version(str(repo), ref="v1")
