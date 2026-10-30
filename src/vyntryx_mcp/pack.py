"""Package a source tree for upload: deterministic .tar.gz, secrets and junk excluded, symlinks never followed.

Always excluded (not overridable): secret-looking files (.env*, *.pem, *.key, id_rsa*, ...), `.git/config`, `.git/`
unless history is requested, dependency/build directories, every symlink, non-regular files, files over 25 MB.
`.gitignore` files (root and nested) and caller-supplied patterns (gitignore syntax) are honoured on top.
"""
from __future__ import annotations

import fnmatch
import gzip
import os
import stat
import tarfile
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pathspec

MAX_FILES = 20_000
MAX_RAW_BYTES = 250 * 1024 * 1024
MAX_PACKED_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024

SECRET_GLOBS = (".env*", "*.pem", "*.key", "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "*.p12", "*.pfx",
                "*.jks", "*.keystore", ".npmrc", ".pypirc", ".netrc")
SKIP_DIRS = {"node_modules", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__", ".venv", "venv",
             ".tox", ".gradle", "coverage"}


class PackError(Exception):
    pass


@dataclass
class PackPreview:
    files: int = 0
    bytes: int = 0
    packed_bytes: int = 0
    reasons: Counter = field(default_factory=Counter)      # exclusion reason -> count
    skipped_symlinks: list[str] = field(default_factory=list)
    include_git: bool = False

    @property
    def excluded(self) -> int:
        return sum(self.reasons.values())

    def summary(self) -> str:
        why = ", ".join(f"{k} {v}" for k, v in sorted(self.reasons.items())) or "none"
        packed = f", {self.packed_bytes / 2**20:.1f} MB packed" if self.packed_bytes else ""
        return f"{self.files} file{'s' * (self.files != 1)}, {self.bytes / 2**20:.1f} MB{packed}; excluded: {why}"


def _is_secret(name: str) -> bool:
    n = name.lower()
    return any(fnmatch.fnmatchcase(n, g) for g in SECRET_GLOBS)


def _gitignored(specs: dict[str, pathspec.GitIgnoreSpec], rel: str, is_dir: bool) -> bool:
    """Deepest .gitignore with an opinion wins (a `!negation` counts as an opinion)."""
    parts = rel.split("/")
    for depth in range(len(parts) - 1, -1, -1):
        spec = specs.get("/".join(parts[:depth]))
        if spec is None:
            continue
        sub = "/".join(parts[depth:]) + ("/" if is_dir else "")
        res = spec.check_file(sub).include
        if res is not None:
            return res
    return False


def plan_tree(root: str | Path, *, exclude: list[str] | None = None, include_git: bool = False,
              max_files: int = MAX_FILES, max_bytes: int = MAX_RAW_BYTES):
    """Walk `root` -> ([(rel, size, executable)], PackPreview). Raises PackError over the caps."""
    root = Path(root)
    if not root.is_dir():
        raise PackError(f"{root} is not an existing directory")
    root = root.resolve()
    if root == Path(root.anchor) or root == Path.home().resolve():
        raise PackError("refusing to package a filesystem root or your whole home directory: pick the project folder")
    user = pathspec.GitIgnoreSpec.from_lines(exclude or [])
    prev, files, total = PackPreview(include_git=include_git), [], 0
    specs: dict[str, pathspec.GitIgnoreSpec] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        in_git = rel_dir == ".git" or rel_dir.startswith(".git/")
        gi = os.path.join(dirpath, ".gitignore")
        if not in_git and os.path.isfile(gi) and not os.path.islink(gi):
            try:
                specs[rel_dir] = pathspec.GitIgnoreSpec.from_lines(Path(gi).read_text(errors="replace").splitlines())
            except OSError:
                pass
        keep = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}".lstrip("/")
            if os.path.islink(os.path.join(dirpath, d)):
                prev.skipped_symlinks.append(rel)
                prev.reasons["symlink"] += 1
            elif d == ".git" and not include_git:
                prev.reasons["vcs"] += 1
            elif d in SKIP_DIRS:
                prev.reasons["deps_build"] += 1
            elif not in_git and _gitignored(specs, rel, True):
                prev.reasons["gitignore"] += 1
            elif user.match_file(rel + "/"):
                prev.reasons["user"] += 1
            else:
                keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            rel, ab = f"{rel_dir}/{f}".lstrip("/"), os.path.join(dirpath, f)
            st = os.lstat(ab)
            if stat.S_ISLNK(st.st_mode):
                prev.skipped_symlinks.append(rel)
                prev.reasons["symlink"] += 1
            elif not stat.S_ISREG(st.st_mode):
                prev.reasons["special"] += 1
            elif f == ".git" and not include_git:
                prev.reasons["vcs"] += 1
            elif _is_secret(f) or rel == ".git/config":
                prev.reasons["secret"] += 1
            elif not in_git and _gitignored(specs, rel, False):
                prev.reasons["gitignore"] += 1
            elif user.match_file(rel):
                prev.reasons["user"] += 1
            elif st.st_size > MAX_FILE_BYTES:
                prev.reasons["too_large"] += 1
            else:
                total += st.st_size
                if len(files) + 1 > max_files:
                    raise PackError(f"more than {max_files} files after exclusions: pick a smaller folder or add exclude patterns")
                if total > max_bytes:
                    raise PackError(f"source is larger than {max_bytes // 2**20} MB ({max_bytes} bytes) after exclusions")
                files.append((rel, st.st_size, bool(st.st_mode & 0o111)))
    if not files:
        raise PackError("nothing to upload after exclusions")
    prev.files, prev.bytes = len(files), total
    return files, prev


def build_archive(root: str | Path, *, exclude: list[str] | None = None, include_git: bool = False,
                  max_files: int = MAX_FILES, max_bytes: int = MAX_RAW_BYTES, max_packed: int = MAX_PACKED_BYTES):
    """-> (path of a temp .tar.gz the caller must delete, PackPreview). Same input => byte-identical archive."""
    files, prev = plan_tree(root, exclude=exclude, include_git=include_git, max_files=max_files, max_bytes=max_bytes)
    root = Path(root).resolve()
    fd, tmp = tempfile.mkstemp(prefix="vyntryx-src-", suffix=".tar.gz")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz, \
                tarfile.open(fileobj=gz, mode="w") as tf:
            for rel, size, executable in files:  # sorted by os.walk order above: dirs and files sorted per level
                ti = tarfile.TarInfo(rel)
                ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = size, 0o755 if executable else 0o644, 0, 0, 0, "", ""
                try:
                    fh = os.fdopen(os.open(root / rel, os.O_RDONLY | os.O_NOFOLLOW), "rb")  # a swapped-in symlink fails here
                except OSError as e:
                    raise PackError(f"{rel} changed while packaging: {e.strerror}") from None
                with fh:
                    if os.fstat(fh.fileno()).st_size != size:
                        raise PackError(f"{rel} changed while packaging")
                    tf.addfile(ti, fh)
        prev.packed_bytes = os.path.getsize(tmp)
        if prev.packed_bytes > max_packed:
            raise PackError(f"packed archive is {prev.packed_bytes // 2**20} MB, over the {max_packed // 2**20} MB limit")
    except BaseException:
        os.unlink(tmp)
        raise
    return tmp, prev
