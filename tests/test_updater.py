"""Tests for the GitHub self-updater helpers."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.updater import (  # noqa: E402
    _replace,
    apply_command,
    build_api_url,
    is_newer,
    normalize_version,
    parse_release,
    replace_tree,
    restart_command,
    rollback_command,
    staging_dir,
    validate_members,
    validate_repo,
    validate_tag,
)

import errno  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
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


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all updater tests passed")
