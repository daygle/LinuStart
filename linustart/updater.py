"""Self-update from GitHub releases.

The GUI checks ``/update/check`` for a newer tagged release; installing runs
this module as a background job (``python -m linustart.updater apply``) so the
whole update shows up as a live log in the Jobs view.

An update:

1. downloads the release tarball from GitHub,
2. refuses archives that are not a single top-level directory with safe paths,
3. backs the current application tree up to ``/var/lib/linustart/backups``,
4. swaps the tree at ``/opt/linustart/app`` (or ``$LINUSTART_APP_DIR``),
5. re-installs it into the panel's own venv and verifies the new version,
6. schedules a ``systemctl restart linustart`` a few seconds later.

If verification fails the old tree is restored automatically, and
``python -m linustart.updater rollback`` restores the most recent backup at
any time. Pure helpers are testable without root or network access.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__

DEFAULT_REPO = "daygle/LinuStart"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_RE = re.compile(r"^v?\d{1,4}(\.\d{1,4}){0,3}([-.][0-9A-Za-z.]+)?$")
USER_AGENT = "LinuStart-Updater"
DOWNLOAD_TIMEOUT = 120
API_TIMEOUT = 15


class NoReleases(RuntimeError):
    """The repository has no published GitHub releases yet."""


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def normalize_version(version: str) -> str:
    return str(version or "").strip().lstrip("vV")


def version_key(version: str) -> Tuple[Tuple[Tuple[int, int, str], ...], Tuple[int, str]]:
    """Sort key for versions like 0.2.0, v1.3, 1.0.0-rc1 (pre-releases sort first)."""
    normalized = normalize_version(version)
    core, _, suffix = normalized.partition("-")
    parts: List[Tuple[int, int, str]] = []
    for piece in core.split("."):
        piece = piece.strip()
        if piece.isdigit():
            parts.append((1, int(piece), ""))
        else:
            parts.append((0, 0, piece))
    pre = (0, suffix) if suffix else (1, "")
    return (tuple(parts), pre)


def is_newer(latest: str, current: str) -> bool:
    return version_key(latest) > version_key(current)


def validate_repo(repo: str) -> str:
    repo = (repo or "").strip()
    if not REPO_RE.match(repo):
        raise ValueError(f"not a valid GitHub repository slug: {repo!r}")
    for part in repo.split("/"):
        if part in (".", "..") or not part.strip("._-"):
            raise ValueError(f"not a valid GitHub repository slug: {repo!r}")
    return repo


def validate_tag(tag: str) -> str:
    tag = (tag or "").strip()
    if not TAG_RE.match(tag):
        raise ValueError(f"not a valid release tag: {tag!r}")
    return tag


def build_api_url(repo: str, path: str) -> str:
    return f"https://api.github.com/repos/{validate_repo(repo)}/{path.lstrip('/')}"


def parse_release(data: object) -> Dict[str, str]:
    """Extract the fields the updater needs from a GitHub release payload."""
    if not isinstance(data, dict):
        raise ValueError("unexpected GitHub API response")
    tag = data.get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        raise ValueError("that GitHub release has no tag_name")
    tarball = data.get("tarball_url")
    if not isinstance(tarball, str) or not tarball.startswith("https://"):
        raise ValueError("that GitHub release has no tarball_url")
    return {
        "tag": tag.strip(),
        "name": str(data.get("name") or tag).strip(),
        "url": str(data.get("html_url") or "").strip(),
        "tarball_url": tarball,
        "published_at": str(data.get("published_at") or "").strip(),
        "body": str(data.get("body") or "").strip()[:2000],
    }


def validate_members(names: Sequence[str]) -> str:
    """Return the archive's single top-level directory; refuse unsafe members."""
    top: Optional[str] = None
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"refusing to extract unsafe archive member: {name}")
        parts = [part for part in path.parts if part not in ("", ".")]
        if not parts:
            continue
        if top is None:
            top = parts[0]
        elif parts[0] != top:
            raise ValueError("the archive is not a single top-level directory")
    if top is None:
        raise ValueError("the archive is empty")
    return top


def app_source_dir() -> Path:
    """Where the application tree lives (what install.sh calls SRC_DIR)."""
    env = os.environ.get("LINUSTART_APP_DIR")
    if env:
        return Path(env)
    default = Path("/opt/linustart/app")
    if default.is_dir():
        return default
    return Path(__file__).resolve().parent.parent


def is_managed_install() -> bool:
    """True when the tree looks like an install.sh layout (or an override)."""
    app_dir = app_source_dir()
    return (app_dir / "pyproject.toml").is_file() and (app_dir / "linustart").is_dir()


def apply_command(repo: str, tag: str = "") -> List[str]:
    argv = [sys.executable, "-m", "linustart.updater", "apply", "--repo", validate_repo(repo)]
    if tag:
        argv += ["--tag", validate_tag(tag)]
    return argv


def rollback_command() -> List[str]:
    return [sys.executable, "-m", "linustart.updater", "rollback"]


def restart_command() -> List[str]:
    return [
        "systemd-run",
        "--on-active=5",
        "--unit=linustart-update-restart",
        "systemctl",
        "restart",
        "linustart.service",
    ]


# --------------------------------------------------------------------------
# Network + filesystem steps (run inside the update job)
# --------------------------------------------------------------------------

def log(message: str) -> None:
    print(message, flush=True)


def fetch_json(url: str) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError(f"not found on GitHub: {url}")
        if exc.code == 403:
            raise RuntimeError("GitHub API rate limit hit; try again later")
        raise RuntimeError(f"GitHub API error {exc.code} for {url}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach GitHub: {exc.reason}")


def latest_release(repo: str) -> Dict[str, str]:
    try:
        return parse_release(fetch_json(build_api_url(repo, "releases/latest")))
    except RuntimeError as exc:
        if "not found on GitHub" in str(exc):
            raise NoReleases(f"no releases are published on GitHub for {repo} yet")
        raise


def download(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response, dest.open("wb") as handle:
            shutil.copyfileobj(response, handle)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"download failed: {exc.reason}")


def extract_tree(archive: Path, dest: Path) -> Path:
    with tarfile.open(archive, "r:gz") as tar:
        top = validate_members([member.name for member in tar.getmembers()])
        try:
            # Python 3.12+ can filter members; 3.14 rejects archives that do
            # not opt in, and the DeprecationWarning is noise in job logs.
            tar.extractall(dest, filter="data")
        except TypeError:  # older interpreters have no filter argument
            tar.extractall(dest)
    return dest / top


def backup_tree(app_dir: Path, backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    target = backup_dir / f"linustart-app-{stamp}.tar.gz"
    with tarfile.open(target, "w:gz") as tar:
        tar.add(str(app_dir), arcname="app")
    return target


def newest_backup(backup_dir: Path) -> Optional[Path]:
    if not backup_dir.is_dir():
        return None
    backups = sorted(backup_dir.glob("linustart-app-*.tar.gz"))
    return backups[-1] if backups else None


def pip_install(target: Path) -> None:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", str(target)],
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"could not run pip: {exc}")
    if result.returncode != 0:
        raise RuntimeError(f"pip install failed: {result.stderr.strip() or result.stdout.strip()}")


def installed_version() -> str:
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import linustart; print(linustart.__version__)"],
            capture_output=True,
            text=True,
        )
    except OSError:
        return ""
    return (result.stdout or "").strip()


def schedule_restart() -> None:
    try:
        result = subprocess.run(restart_command(), capture_output=True, text=True)
    except OSError:
        result = None
    if result is not None and result.returncode == 0:
        log("service restart scheduled in ~5 seconds (systemctl restart linustart)")
    else:
        log("could not schedule the restart automatically; run: systemctl restart linustart")


@contextlib.contextmanager
def staging_dir(app_dir: Path):
    """Scratch space on the *same filesystem* as the application tree.

    The obvious choice, /tmp, is usually tmpfs while /opt is not, and
    os.replace cannot rename across filesystems - the update would die with
    EXDEV after the backup was already written.
    """
    try:
        path = tempfile.mkdtemp(prefix=".linustart-update-", dir=str(app_dir.parent))
    except OSError:
        path = tempfile.mkdtemp(prefix="linustart-update-")
    try:
        yield Path(path)
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _replace(src: Path, dst: Path) -> None:
    """Rename src onto dst, coping with a cross-device move."""
    try:
        os.replace(src, dst)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        if dst.is_dir() and not dst.is_symlink():
            shutil.rmtree(dst)
        elif dst.exists():
            dst.unlink()
        shutil.move(str(src), str(dst))


def replace_tree(app_dir: Path, new_tree: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    old = app_dir.parent / f".linustart-old-{stamp}"
    _replace(app_dir, old)
    try:
        _replace(new_tree, app_dir)
    except OSError:
        _replace(old, app_dir)
        raise
    return old


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_apply(repo: str, tag: str = "", tarball: str = "") -> int:
    from .paths import BACKUP_DIR

    app_dir = app_source_dir()
    if not is_managed_install():
        log(f"refusing to update: {app_dir} does not look like a LinuStart install")
        log("(source checkouts should use 'git pull'; installs live in /opt/linustart/app)")
        return 1

    log(f"current version: {__version__}  (repo {repo})")
    if tarball:
        tag = validate_tag(tag) if tag else __version__
        log(f"using local archive {tarball} (tag {tag})")
    elif tag:
        tag = validate_tag(tag)
        tarball_url = build_api_url(repo, f"tarball/{tag}")
        log(f"using release tag {tag}")
    else:
        release = latest_release(repo)
        tag = release["tag"]
        tarball_url = release["tarball_url"]
        log(f"latest release: {tag} ({release['published_at'] or 'no date'})")

    with staging_dir(app_dir) as tmp:
        tmp_path = tmp
        if tarball:
            archive = Path(tarball)
            if not archive.is_file():
                log(f"no such archive: {archive}")
                return 1
        else:
            archive = tmp_path / "release.tar.gz"
            log(f"downloading {tarball_url}")
            download(tarball_url, archive)
            log(f"downloaded {archive.stat().st_size} bytes")

        log("verifying and extracting the archive")
        try:
            new_tree = extract_tree(archive, tmp_path / "src")
        except (ValueError, tarfile.TarError) as exc:
            log(f"refusing the archive: {exc}")
            return 1
        if not (new_tree / "linustart" / "__init__.py").is_file() or not (new_tree / "pyproject.toml").is_file():
            log("refusing the archive: it does not contain a LinuStart application")
            return 1

        log("backing up the current application tree")
        backup = backup_tree(app_dir, BACKUP_DIR)
        log(f"backup written to {backup}")

        log("installing the new tree")
        old_tree = replace_tree(app_dir, new_tree)
        try:
            log("installing into the Python environment")
            pip_install(app_dir)
            new_version = installed_version()
            expected = normalize_version(tag)
            if new_version and normalize_version(new_version) != expected:
                raise RuntimeError(f"installed version {new_version} does not match release {tag}")
            log(f"installed LinuStart {new_version}")
        except Exception as exc:  # noqa: BLE001 - restore and report
            log(f"update failed: {exc}")
            log("restoring the previous version")
            shutil.rmtree(app_dir, ignore_errors=True)
            _replace(old_tree, app_dir)
            try:
                pip_install(app_dir)
                log("previous version restored")
            except Exception as restore_exc:  # noqa: BLE001
                log(f"restore also failed: {restore_exc} (backup: {backup})")
            return 1

        shutil.rmtree(old_tree, ignore_errors=True)

    log(f"update to {tag} complete")
    schedule_restart()
    return 0


def cmd_rollback() -> int:
    from .paths import BACKUP_DIR

    app_dir = app_source_dir()
    if not is_managed_install():
        log(f"refusing to roll back: {app_dir} does not look like a LinuStart install")
        return 1
    backup = newest_backup(BACKUP_DIR)
    if backup is None:
        log(f"no application backup found in {BACKUP_DIR}")
        return 1
    log(f"restoring {backup}")
    with staging_dir(app_dir) as tmp:
        try:
            tree = extract_tree(backup, tmp)
        except (ValueError, tarfile.TarError) as exc:
            log(f"backup is unusable: {exc}")
            return 1
        old_tree = replace_tree(app_dir, tree / "app" if (tree / "app").is_dir() else tree)
    shutil.rmtree(old_tree, ignore_errors=True)
    try:
        pip_install(app_dir)
    except Exception as exc:  # noqa: BLE001
        log(f"pip install failed: {exc}")
        return 1
    log(f"rolled back to version {installed_version()}")
    schedule_restart()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="linustart-updater", description="Update LinuStart from GitHub releases")
    sub = parser.add_subparsers(dest="command", required=True)
    apply_parser = sub.add_parser("apply", help="download and install the latest (or a specific) release")
    apply_parser.add_argument("--repo", default=DEFAULT_REPO, help=f"GitHub repository slug (default {DEFAULT_REPO})")
    apply_parser.add_argument("--tag", default="", help="release tag to install (default: latest release)")
    apply_parser.add_argument("--tarball", default="", help="install from a local release tarball instead of GitHub")
    sub.add_parser("rollback", help="restore the most recent application backup")
    args = parser.parse_args(argv)
    if args.command == "apply":
        return cmd_apply(args.repo, args.tag, args.tarball)
    return cmd_rollback()


if __name__ == "__main__":
    raise SystemExit(main())
