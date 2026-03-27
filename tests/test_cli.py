"""Tests for CLI commands."""
from typer.testing import CliRunner
from kahlo.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "frida-kahlo" in result.output


def test_device():
    result = runner.invoke(app, ["device"])
    assert result.exit_code == 0


def test_device_shows_root_status():
    result = runner.invoke(app, ["device"])
    assert result.exit_code == 0
    assert "root" in result.output.lower() or "magisk" in result.output.lower()
