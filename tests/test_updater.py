"""Tests for the GitHub self-updater helpers."""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.updater import (  # noqa: E402
    _replace,
    apply_command,
    build_api_url,
    describe_checkout,
    is_managed_install,
    is_newer,
    is_source_checkout,
    normalize_version,
    parse_describe,
    parse_release,
    replace_tree,
    restart_command,
    rollback_command,
    running_version,
    staging_dir,
    validate_members,
    validate_repo,
    validate_tag,
    version_details,
    version_key,
)

import errno  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402

RELEASE = {
    "tag_name": "v0.2.0",
    "name": "LinuStart 0.2.0",
    "html_url": "https://github.com/daygle/LinuStart/releases/tag/v0.2.0",
    "tarball_url": "https://api.github.com/repos/daygle/LinuStart/tarball/v0.2.0",
    "published_at": "2026-10-03T00:00:00Z",
    "body": "## Changes\n* self-update support",
}


def test_normalize_version():
    assert normalize_version("v0.2.0") == "0.2.0"
    assert normalize_version(" V1.3 ") == "1.3"
    assert normalize_version("") == ""


def test_is_newer():
    assert is_newer("v0.2.0", "0.1.0")
    assert is_newer("0.10.0", "0.9.9")  # numeric, not lexicographic
    assert is_newer("1.0.0", "1.0")
    assert not is_newer("0.1.0", "0.1.0")
    assert not is_newer("v0.1.0", "0.2.0")
    assert not is_newer("0.1.0-rc1", "0.1.0")  # pre-releases sort first
    assert is_newer("0.1.0", "0.1.0-rc1")


def test_validate_repo():
    assert validate_repo("daygle/LinuStart") == "daygle/LinuStart"
    for bad in ["", "just-a-name", "a/b/c", "https://github.com/x/y", "x/y; rm -rf /", "../etc"]:
        try:
            validate_repo(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_validate_tag():
    assert validate_tag("v0.2.0") == "v0.2.0"
    assert validate_tag("1.2.3-rc1") == "1.2.3-rc1"
    for bad in ["", "latest", "v0.2.0; reboot", "a/b", "$(whoami)", "v0.2.0 ../../etc"]:
        try:
            validate_tag(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_build_api_url():
    assert build_api_url("daygle/LinuStart", "releases/latest") == (
        "https://api.github.com/repos/daygle/LinuStart/releases/latest"
    )


def test_parse_release():
    release = parse_release(RELEASE)
    assert release["tag"] == "v0.2.0"
    assert release["tarball_url"].startswith("https://")
    assert "self-update" in release["body"]


def test_parse_release_rejects_junk():
    for bad in [None, [], "nope", {}, {"tag_name": "v1"}, {"tag_name": "v1", "tarball_url": "http://insecure"}]:
        try:
            parse_release(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_validate_members_accepts_normal_archive():
    top = validate_members(["daygle-LinuStart-abc123/", "daygle-LinuStart-abc123/linustart/__init__.py"])
    assert top == "daygle-LinuStart-abc123"


def test_validate_members_rejects_traversal():
    for bad in [["../evil"], ["/etc/passwd"], ["ok/a", "other/b"], []]:
        try:
            validate_members(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_commands():
    argv = apply_command("daygle/LinuStart", "v0.2.0")
    assert argv[1:4] == ["-m", "linustart.updater", "apply"]
    assert argv[-2:] == ["--tag", "v0.2.0"]
    assert "daygle/LinuStart" in argv
    assert rollback_command()[1:4] == ["-m", "linustart.updater", "rollback"]
    assert restart_command()[-2:] == ["restart", "linustart.service"]
    try:
        apply_command("daygle/LinuStart", "v0.2.0; rm -rf /")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a hostile tag")


def test_staging_dir_lives_beside_the_app():
    """The swap is a rename, so staging must share the app's filesystem."""
    with tempfile.TemporaryDirectory() as tmp:
        app_dir = pathlib.Path(tmp) / "opt" / "linustart" / "app"
        app_dir.mkdir(parents=True)
        with staging_dir(app_dir) as staging:
            assert staging.parent == app_dir.parent
            assert staging.is_dir()
        assert not staging.exists()  # cleaned up on exit


def test_replace_falls_back_when_filesystems_differ():
    """/tmp on tmpfs and /opt on the root fs made os.replace raise EXDEV."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        src = root / "src"
        src.mkdir()
        (src / "file.txt").write_text("new tree")
        dst = root / "dst"

        real_replace = os.replace

        def refuse(*_args, **_kwargs):
            raise OSError(errno.EXDEV, "Invalid cross-device link")

        os.replace = refuse
        try:
            _replace(src, dst)
        finally:
            os.replace = real_replace
        assert not src.exists()
        assert (dst / "file.txt").read_text() == "new tree"


def test_replace_tree_swaps_and_can_undo():
    with tempfile.TemporaryDirectory() as tmp:
        app_dir = pathlib.Path(tmp) / "app"
        app_dir.mkdir()
        (app_dir / "version.txt").write_text("old")
        new_tree = app_dir.parent / "new"
        new_tree.mkdir()
        (new_tree / "version.txt").write_text("new")

        old_tree = replace_tree(app_dir, new_tree)
        assert (app_dir / "version.txt").read_text() == "new"
        assert (old_tree / "version.txt").read_text() == "old"
        # the previous tree is where a rollback would come from
        assert old_tree.parent == app_dir.parent


def test_version_is_the_single_source_of_truth():
    """The tag, the package metadata and the running code must agree.

    A release tagged v1.0.0 while the code still said 0.1.0 made the
    updater roll every install straight back, so pin the two together.
    """
    import linustart

    root = pathlib.Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', pyproject, re.M)
    assert declared, "pyproject.toml has no static version"
    assert declared.group(1) == linustart.__version__
    assert re.fullmatch(r"\d{1,4}(\.\d{1,4}){0,3}(-[0-9A-Za-z.]+)?", linustart.__version__), (
        f"version {linustart.__version__!r} would not pass validate_tag when tagged"
    )
    # the updater compares the installed version against the tag
    assert normalize_version("v" + linustart.__version__) == linustart.__version__
    assert validate_tag("v" + linustart.__version__)


# --- what the panel reports it is running ----------------------------------

def test_parse_describe():
    assert parse_describe("v1.0.0-3-g0cdaeb8\n") == ("1.0.0", 3, "0cdaeb8")
    assert parse_describe("v1.2.0-0-gabcdef1234567890") == ("1.2.0", 0, "abcdef1234567890")
    # no tag, no git, a shallow clone: we must not guess how far ahead we are
    for junk in ["", "   ", "fatal: No names found\n", "v1.0.0\n", "1.0.0-3-gnothex\n"]:
        assert parse_describe(junk) is None, junk


def test_version_details_matches_the_source_it_runs_from():
    """Git data when git can describe the tree, the declared version when not.

    Branch on what describe_checkout() actually returns, not on whether a
    .git directory exists: a shallow or tagless clone has one but cannot be
    described, and must not claim to be reporting git data.
    """
    import linustart

    described = describe_checkout()
    details = version_details()
    if described:
        tag, distance, commit = described
        assert details["source"] == "git"
        assert details["base"] == tag
        assert details["version"] == f"{tag}-{distance}-g{commit}"
        assert details["ahead"] == distance
    else:
        # A release tarball has no repository to ask, and neither has a
        # shallow checkout with no tag - report the declared version rather
        # than guessing how far ahead of a tag anything is.
        assert details["source"] == "declared"
        assert details["version"] == linustart.__version__
        assert details["ahead"] is None
    assert running_version() == details["version"]
    assert version_key(details["base"])  # comparable against a release tag


def test_declared_version_is_never_ahead_of_the_newest_tag():
    """A version past every tag would hide in-panel updates for good.

    /update/check compares the newest release against what is installed; if
    the declared version runs ahead of the last release there is nothing left
    to offer, and the panel says 'up to date' while running unreleased code.
    Bump the version on main only together with cutting the tag.
    """
    import linustart

    try:
        tags = subprocess.run(
            ["git", "tag", "--list"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return  # no git here (the standalone runner, a tarball export)
    if tags.returncode != 0 or not tags.stdout.strip():
        return  # not a checkout, or no release has been tagged yet
    newest = max((t.strip() for t in tags.stdout.splitlines() if t.strip()), key=version_key)
    assert not is_newer(linustart.__version__, newest), (
        f"__version__ {linustart.__version__} is ahead of the newest tag {newest}: "
        "tag the release (or revert the bump) or the GUI will never offer an update"
    )


def test_a_checkout_is_not_a_managed_install():
    """In-panel updates must never overwrite somebody's working tree."""
    with tempfile.TemporaryDirectory() as tmp:
        app_dir = pathlib.Path(tmp)
        (app_dir / "pyproject.toml").write_text("", encoding="utf-8")
        (app_dir / "linustart").mkdir()
        previous = os.environ.get("LINUSTART_APP_DIR")
        os.environ["LINUSTART_APP_DIR"] = str(app_dir)
        try:
            assert is_managed_install()  # an install.sh layout: updatable
            assert not is_source_checkout()
            (app_dir / ".git").mkdir()  # now it is somebody's clone
            assert is_source_checkout()
            assert not is_managed_install()
        finally:
            if previous is None:
                os.environ.pop("LINUSTART_APP_DIR", None)
            else:
                os.environ["LINUSTART_APP_DIR"] = previous


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all updater tests passed")


# --------------------------------------------------------------------------
# Verified downloads and unit refresh
# --------------------------------------------------------------------------

import hashlib  # noqa: E402

from linustart import updater as updater_mod  # noqa: E402

RELEASE_WITH_ASSETS = {
    "tag_name": "v1.2.0",
    "tarball_url": "https://api.github.com/repos/daygle/LinuStart/tarball/v1.2.0",
    "assets": [
        {"name": "linustart-v1.2.0.tar.gz",
         "browser_download_url": "https://github.com/daygle/LinuStart/releases/download/v1.2.0/linustart-v1.2.0.tar.gz"},
        {"name": "SHA256SUMS",
         "browser_download_url": "https://github.com/daygle/LinuStart/releases/download/v1.2.0/SHA256SUMS"},
        {"name": "evil", "browser_download_url": "http://example.com/x"},
    ],
}


def test_release_assets_are_parsed_and_foreign_hosts_dropped():
    assets = parse_release(RELEASE_WITH_ASSETS)["assets"]
    assert set(assets) == {"linustart-v1.2.0.tar.gz", "SHA256SUMS"}


def test_choose_download_prefers_the_verifiable_asset():
    url, name, sums = updater_mod.choose_download(parse_release(RELEASE_WITH_ASSETS))
    assert name == "linustart-v1.2.0.tar.gz" and url.endswith(name) and sums.endswith("SHA256SUMS")
    bare = dict(RELEASE_WITH_ASSETS, assets=[])
    url, name, sums = updater_mod.choose_download(parse_release(bare))
    assert url.endswith("tarball/v1.2.0") and sums is None


def test_verify_checksum(tmp_path):
    archive = tmp_path / "linustart-v1.2.0.tar.gz"
    archive.write_bytes(b"payload")
    digest = hashlib.sha256(b"payload").hexdigest()
    sums = f"{digest}  linustart-v1.2.0.tar.gz\n{'0' * 64}  other\n"
    assert updater_mod.verify_checksum(archive, archive.name, sums) == digest
    with pytest.raises(ValueError):
        updater_mod.verify_checksum(archive, archive.name, f"{'1' * 64}  {archive.name}\n")
    with pytest.raises(ValueError):
        updater_mod.verify_checksum(archive, archive.name, "")


def test_require_checksum_flag_reaches_the_job():
    assert apply_command("daygle/LinuStart", "", True)[-1] == "--require-checksum"
    assert "--require-checksum" not in apply_command("daygle/LinuStart")


def test_downloads_are_limited_to_github(tmp_path):
    with pytest.raises(RuntimeError):
        updater_mod.download("https://example.com/x.tar.gz", tmp_path / "x")
    with pytest.raises(RuntimeError):
        updater_mod.fetch_text("http://github.com/x")


def test_refresh_unit_replaces_only_a_changed_installed_unit(tmp_path, monkeypatch):
    from linustart import util

    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    app = tmp_path / "app"
    (app / "systemd").mkdir(parents=True)
    (app / "systemd" / "linustart.service").write_text("[Service]\nProtectHome=false\n")
    unit = tmp_path / "linustart.service"
    monkeypatch.setattr(updater_mod, "installed_unit_path", lambda: unit)
    ran = []
    monkeypatch.setattr(updater_mod.subprocess, "run", lambda argv, **kw: ran.append(argv))
    assert updater_mod.refresh_unit(app) is False  # no install.sh unit: leave alone
    unit.write_text("[Service]\nProtectHome=true\n")
    assert updater_mod.refresh_unit(app) is True
    assert "ProtectHome=false" in unit.read_text()
    assert ran == [["systemctl", "daemon-reload"]]
    assert updater_mod.refresh_unit(app) is False  # already current


def test_declared_version_reads_the_unpacked_tree(tmp_path):
    (tmp_path / "linustart").mkdir()
    assert updater_mod.declared_version(tmp_path) == ""
    (tmp_path / "linustart" / "__init__.py").write_text('"""x"""\n\n__version__ = "1.0.3"\n', encoding="utf-8")
    assert updater_mod.declared_version(tmp_path) == "1.0.3"


def test_a_release_tagged_without_a_version_bump_is_refused_untouched(tmp_path, monkeypatch):
    """v1.0.2 shipped declaring 1.0.0: refuse it before backing up or swapping."""
    import tarfile

    src = tmp_path / "linustart-v1.0.2"
    (src / "linustart").mkdir(parents=True)
    (src / "linustart" / "__init__.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    (src / "pyproject.toml").write_text('version = "1.0.0"\n', encoding="utf-8")
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(str(src), arcname=src.name)

    app_dir = tmp_path / "opt" / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "marker").write_text("old", encoding="utf-8")
    monkeypatch.setattr(updater_mod, "app_source_dir", lambda: app_dir)
    monkeypatch.setattr(updater_mod, "is_managed_install", lambda: True)

    def untouched(*_args, **_kwargs):
        raise AssertionError("the install must not be touched")

    monkeypatch.setattr(updater_mod, "backup_tree", untouched)
    monkeypatch.setattr(updater_mod, "replace_tree", untouched)
    monkeypatch.setattr(updater_mod, "pip_install", untouched)

    assert updater_mod.cmd_apply("daygle/LinuStart", tag="v1.0.2", tarball=str(archive)) == 1
    assert (app_dir / "marker").read_text(encoding="utf-8") == "old"
