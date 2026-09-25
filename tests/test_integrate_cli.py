"""Unit tests for integrate scaffolding and new CLI commands (no network)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from smart_token_prod.cli import main
from smart_token_prod.integrate import (
    DEFAULT_GIT_DEP,
    detect_project,
    run_integrate,
)


def test_version_exits_zero(capsys):
    rc = main(["version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == "0.10.5"


def test_doctor_exits_zero(capsys):
    rc = main(["doctor"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "status():" in out
    assert "version" in out


def test_print_dep_git(capsys):
    rc = main(["print-dep"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "smart-token-prod @" in out
    assert "Smart-Token-Prod.git@v0.10.5" in out


def test_print_dep_editable(capsys, tmp_path):
    rc = main(["print-dep", "--editable", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("pip install -e ")
    assert str(tmp_path.resolve()) in out


def test_integrate_dry_run(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    rc = main(["integrate", str(tmp_path), "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run" in out
    assert not (tmp_path / "smart_token_bridge.py").exists()
    assert not (tmp_path / "INTEGRATION.smart-token.md").exists()
    # requirements untouched
    assert tmp_path.joinpath("requirements.txt").read_text(encoding="utf-8") == "flask\n"


def test_integrate_real_write_requirements(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    # also simulate old vendor tree
    vendor = tmp_path / "vendor" / "smart_token_prod"
    vendor.mkdir(parents=True)
    (vendor / "__init__.py").write_text("# old\n", encoding="utf-8")

    rc = main(["integrate", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "vendor" in out.lower() or "FOUND" in out

    bridge = tmp_path / "smart_token_bridge.py"
    notes = tmp_path / "INTEGRATION.smart-token.md"
    assert bridge.is_file()
    assert notes.is_file()
    assert "protect_artifact" in bridge.read_text(encoding="utf-8")
    req = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    assert "flask" in req
    assert "smart-token-prod" in req
    assert DEFAULT_GIT_DEP.split("@")[0].strip() in req or "smart-token-prod @" in req


def test_integrate_pyproject_only_writes_hint(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.0.1"\n',
        encoding="utf-8",
    )
    summary = run_integrate(tmp_path, dry_run=False)
    assert summary["detect"]["kind"] == "pyproject"
    hint = tmp_path / "requirements-smart-token.txt"
    assert hint.is_file()
    assert "smart-token-prod" in hint.read_text(encoding="utf-8")
    assert (tmp_path / "INTEGRATION.generated.md").is_file()
    assert (tmp_path / "smart_token_bridge.py").is_file()
    # TOML not blindly rewritten
    assert '[project]\nname = "demo"' in (tmp_path / "pyproject.toml").read_text(
        encoding="utf-8"
    )


def test_integrate_custom_bridge_and_editable(tmp_path):
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    editable = tmp_path / "local-stp"
    editable.mkdir()
    summary = run_integrate(
        tmp_path,
        bridge_path="src/stp_bridge.py",
        mode="editable",
        editable_path=editable,
        dry_run=False,
    )
    assert (tmp_path / "src" / "stp_bridge.py").is_file()
    req = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    assert req.strip().startswith("-e ")
    assert str(editable.resolve()) in req
    assert summary["dependency"]["mode"] == "editable"


def test_detect_project_unknown(tmp_path):
    info = detect_project(tmp_path)
    assert info["kind"] == "unknown"
    assert info["vendor_stp_path"] is None


def test_integrate_rejects_bridge_escape(tmp_path):
    """D2: --bridge must resolve under project root (no .. / abs outside)."""
    from smart_token_prod.integrate import resolve_bridge_path, write_bridge_module
    import pytest

    (tmp_path / "requirements.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="escapes|absolute"):
        resolve_bridge_path(tmp_path, "../evil_bridge.py")
    with pytest.raises(ValueError, match="absolute|escapes"):
        resolve_bridge_path(tmp_path, "/tmp/evil_bridge.py")
    # CLI path
    with pytest.raises(ValueError):
        write_bridge_module(tmp_path, relative_path="../../outside.py", dry_run=True)


def test_integrate_cli_rejects_bridge_escape(tmp_path, capsys):
    """CLI integrate must exit 2 on bridge escape (no traceback)."""
    (tmp_path / "requirements.txt").write_text("x\n", encoding="utf-8")
    rc = main(["integrate", str(tmp_path), "--bridge", "../evil.py"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error:" in err.lower() or "escape" in err.lower() or "absolute" in err.lower()
