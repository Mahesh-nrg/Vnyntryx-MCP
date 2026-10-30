import hashlib
import os
import tarfile

import pytest

from vyntryx_mcp.pack import PackError, build_archive


def names(archive):
    with tarfile.open(archive) as t:
        return sorted(m.name for m in t.getmembers())


@pytest.fixture
def proj(tmp_path):
    r = tmp_path / "proj"
    for rel, data in {
        "src/app.py": "print(1)\n", "README.md": "hi", ".gitignore": "*.log\nsecrets_dir/\n!keep.log\n",
        "a.log": "x", "keep.log": "y", "secrets_dir/x.py": "z", "src/.gitignore": "gen_*.py\n", "src/gen_a.py": "g",
        ".env": "K=1", ".env.local": "K=2", "cert.pem": "p", "tls/server.key": "k", "id_rsa": "r", "id_rsa.pub": "r",
        "node_modules/m/i.js": "n", "dist/o.js": "o", "build/o.js": "o", "__pycache__/x.pyc": "c",
        ".git/HEAD": "ref", ".git/config": "[remote] url=https://tok@x", ".git/objects/ab": "obj",
    }.items():
        f = r / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(data)
    return r


def test_excludes_secrets_vcs_and_build_output_and_honours_gitignore(proj):
    arc, prev = build_archive(proj)
    try:
        assert names(arc) == [".gitignore", "README.md", "keep.log", "src/.gitignore", "src/app.py"]
        assert prev.files == 5 and prev.excluded > 0 and not prev.include_git
    finally:
        os.unlink(arc)


def test_extra_exclude_patterns(proj):
    arc, _ = build_archive(proj, exclude=["README.md", "src/"])
    try:
        assert names(arc) == [".gitignore", "keep.log"]
    finally:
        os.unlink(arc)


def test_git_history_opt_in_still_drops_git_config_and_secrets(proj):
    arc, prev = build_archive(proj, include_git=True)
    try:
        n = names(arc)
        assert ".git/HEAD" in n and ".git/objects/ab" in n
        assert ".git/config" not in n and ".env" not in n and "id_rsa" not in n and prev.include_git
    finally:
        os.unlink(arc)


def test_symlinks_never_followed_or_stored(proj, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("top secret")
    os.symlink(outside / "secret.txt", proj / "link_file")
    os.symlink(outside, proj / "link_dir")
    os.symlink(proj / "README.md", proj / "link_inside")
    arc, prev = build_archive(proj)
    try:
        n = names(arc)
        assert not any("link" in x or "secret" in x for x in n)
        assert sorted(prev.skipped_symlinks) == ["link_dir", "link_file", "link_inside"]
    finally:
        os.unlink(arc)


def test_deterministic_regardless_of_mtime_and_creation_order(proj):
    a, _ = build_archive(proj)
    for f in proj.rglob("*"):
        if f.is_file():
            os.utime(f, (12345, 12345))
    b, _ = build_archive(proj)
    try:
        assert hashlib.sha256(open(a, "rb").read()).digest() == hashlib.sha256(open(b, "rb").read()).digest()
    finally:
        os.unlink(a), os.unlink(b)


def test_members_are_safe_relative_normalised_and_extract_with_data_filter(proj, tmp_path):
    (proj / "run.sh").write_text("#!/bin/sh\n")
    os.chmod(proj / "run.sh", 0o755)
    arc, _ = build_archive(proj)
    try:
        with tarfile.open(arc) as t:
            for m in t.getmembers():
                assert not m.name.startswith(("/", "./", "../")) and ".." not in m.name.split("/")
                assert m.uid == m.gid == 0 and m.mtime == 0 and m.isreg()
                assert m.mode == (0o755 if m.name == "run.sh" else 0o644)
            dest = tmp_path / "out"
            t.extractall(dest, filter="data")
        assert (dest / "src" / "app.py").read_text() == "print(1)\n"
    finally:
        os.unlink(arc)


def test_caps_refuse(proj):
    with pytest.raises(PackError, match="files"):
        build_archive(proj, max_files=2)
    with pytest.raises(PackError, match="MB|bytes|size"):
        build_archive(proj, max_bytes=3)


def test_bad_roots_and_empty(tmp_path):
    with pytest.raises(PackError):
        build_archive(tmp_path / "missing")
    f = tmp_path / "f.txt"
    f.write_text("x")
    with pytest.raises(PackError):
        build_archive(f)
    (tmp_path / "e").mkdir()
    (tmp_path / "e" / ".env").write_text("K=1")
    with pytest.raises(PackError, match="nothing"):
        build_archive(tmp_path / "e")
