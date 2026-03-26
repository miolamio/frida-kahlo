"""Tests for the pipeline module and CLI integration."""
import os

import pytest


class TestPipelineImport:
    """Test that pipeline module imports correctly."""

    def test_import_pipeline(self):
        from kahlo.pipeline import Pipeline, PipelineStage, PipelineError
        assert Pipeline is not None
        assert PipelineStage.ACQUIRE.value == "ACQUIRE"

    def test_import_acquire(self):
        from kahlo.acquire import APKExtractor, APKFormat, APKInstaller
        assert APKExtractor is not None
        assert APKFormat is not None
        assert APKInstaller is not None

    def test_import_prepare(self):
        from kahlo.prepare import ManifestAnalyzer, ManifestInfo, Decompiler
        assert ManifestAnalyzer is not None
        assert ManifestInfo is not None
        assert Decompiler is not None

    def test_import_fetcher(self):
        from kahlo.acquire.fetcher import APKFetcher
        assert APKFetcher is not None


class TestPipelineCreation:
    """Test pipeline object creation."""

    def test_create_pipeline(self):
        from kahlo.pipeline import Pipeline
        pipeline = Pipeline()
        assert pipeline is not None

    def test_pipeline_error_no_device_no_package(self):
        """Pipeline should fail gracefully with clear error."""
        from kahlo.pipeline import Pipeline, PipelineError
        pipeline = Pipeline()
        # This should fail because "nonexistent_app" is not a package name
        # and skip_fetch needs a package name
        with pytest.raises(PipelineError, match="Cannot skip fetch"):
            pipeline.analyze("nonexistent_app", skip_fetch=True, duration=5)


class TestCLICommands:
    """Test CLI commands exist and are callable."""

    def test_analyze_help(self):
        from typer.testing import CliRunner
        from kahlo.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "duration" in result.output
        assert "skip-fetch" in result.output

    def test_fetch_help(self):
        from typer.testing import CliRunner
        from kahlo.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["fetch", "--help"])
        assert result.exit_code == 0
        assert "query" in result.output.lower() or "QUERY" in result.output

    def test_manifest_help(self):
        from typer.testing import CliRunner
        from kahlo.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["manifest", "--help"])
        assert result.exit_code == 0
        assert "PATH" in result.output

    def test_manifest_yakitoriya(self):
        from typer.testing import CliRunner
        from kahlo.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["manifest", "/Users/codegeek/Lab/android/apps/yakitoriya"])
        assert result.exit_code == 0
        assert "com.voltmobi.yakitoriya" in result.output


class TestManifestAnalysis:
    """Test manifest analysis from CLI."""

    def test_manifest_from_xapk_dir(self):
        from kahlo.prepare.manifest import ManifestAnalyzer
        analyzer = ManifestAnalyzer()
        info = analyzer.analyze("/Users/codegeek/Lab/android/apps/yakitoriya")
        assert info.package_name == "com.voltmobi.yakitoriya"
        assert "android.permission.INTERNET" in info.permissions
        assert info.version_name is not None
