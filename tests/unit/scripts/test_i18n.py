import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest

I18N_PATH = Path(__file__).resolve().parents[3] / "scripts" / "i18n.py"


def _load_i18n_module():
    spec = importlib.util.spec_from_file_location("ddt4all_i18n_script", I18N_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


i18n = _load_i18n_module()


def test_locate_gettext_tool_found_on_path():
    with patch.object(i18n.shutil, "which", return_value=r"C:\tools\xgettext.exe"):
        assert i18n.locate_gettext_tool("xgettext") == r"C:\tools\xgettext.exe"


def test_locate_gettext_tool_skips_git_fallback_on_non_windows(monkeypatch):
    monkeypatch.setattr(i18n.shutil, "which", lambda cmd: None)
    monkeypatch.setattr(i18n.os, "name", "posix")
    assert i18n.locate_gettext_tool("xgettext") is None


@pytest.mark.skipif(i18n.os.name != "nt", reason="Git for Windows gettext fallback is Windows-only")
def test_locate_gettext_tool_falls_back_to_git_bundle(tmp_path, monkeypatch):
    git_root = tmp_path / "Git"
    usr_bin = git_root / "usr" / "bin"
    usr_bin.mkdir(parents=True)
    xgettext = usr_bin / "xgettext.exe"
    xgettext.write_text("")

    git_cmd_dir = git_root / "cmd"
    git_cmd_dir.mkdir(parents=True)
    git_exe = git_cmd_dir / "git.exe"
    git_exe.write_text("")

    def fake_which(cmd):
        return str(git_exe) if cmd == "git" else None

    monkeypatch.setattr(i18n.shutil, "which", fake_which)
    assert i18n.locate_gettext_tool("xgettext") == str(xgettext)


@pytest.mark.skipif(i18n.os.name != "nt", reason="Git for Windows gettext fallback is Windows-only")
def test_locate_gettext_tool_returns_none_when_nothing_found(monkeypatch):
    monkeypatch.setattr(i18n.shutil, "which", lambda cmd: None)
    assert i18n.locate_gettext_tool("xgettext") is None
