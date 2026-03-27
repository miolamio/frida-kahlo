"""Pipeline — full orchestration: ACQUIRE -> PREPARE -> INSTRUMENT -> ANALYZE -> REPORT."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from enum import Enum

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)


class PipelineStage(str, Enum):
    ACQUIRE = "ACQUIRE"
    PREPARE = "PREPARE"
    INSTRUMENT = "INSTRUMENT"
    ANALYZE = "ANALYZE"
    REPORT = "REPORT"


class PipelineError(Exception):
    pass


class Pipeline:
    """Full analysis pipeline: fetch -> install -> scan -> analyze -> report."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._stage = PipelineStage.ACQUIRE
        self._session_dir: str | None = None

    def _status(self, msg: str, style: str = "cyan") -> None:
        """Print status message."""
        self.console.print(f"  [{style}]{msg}[/{style}]")

    def _stage_header(self, stage: PipelineStage) -> None:
        """Print stage header."""
        self._stage = stage
        self.console.print(f"\n[bold blue]>>> {stage.value}[/bold blue]")

    def analyze(
        self,
        target: str,
        duration: int = 60,
        skip_fetch: bool = False,
        skip_static: bool = False,
        output_dir: str | None = None,
    ) -> str:
        """Full pipeline: fetch -> install -> scan -> analyze -> report.

        Args:
            target: App name or package name (com.xxx.yyy).
            duration: Scan duration in seconds.
            skip_fetch: Skip APK download (assume app is installed).
            skip_static: Skip jadx decompilation.
            output_dir: Output directory (default: sessions/).

        Returns:
            Path to the session output directory.
        """
        is_package = "." in target and not target.endswith(".apk")
        package_name = target if is_package else None

        if output_dir is None:
            output_dir = os.path.join(os.getcwd(), "sessions")
        os.makedirs(output_dir, exist_ok=True)

        # ============================================================
        # STAGE 1: ACQUIRE
        # ============================================================
        self._stage_header(PipelineStage.ACQUIRE)

        apk_path: str | None = None
        apk_dir: str | None = None

        if skip_fetch:
            self._status("Skipping APK fetch (--skip-fetch)")
            if not is_package:
                raise PipelineError(
                    f"Cannot skip fetch for non-package target: {target}. "
                    "Use a package name like com.example.app"
                )
        else:
            if is_package:
                self._status(f"Target is a package name: {target}")
                self._status("Checking if already installed...")
                from kahlo.device.adb import ADB
                adb = ADB()
                devices = adb.devices()
                if devices:
                    adb = ADB(serial=devices[0].serial)
                    installed = adb.list_packages()
                    if target in installed:
                        self._status("Already installed on device", "green")
                        skip_fetch = True
                    else:
                        self._status("Not installed — will try to fetch APK", "yellow")
            else:
                self._status(f"Searching for APK: {target}")
                try:
                    from kahlo.acquire.fetcher import APKFetcher
                    fetcher = APKFetcher()
                    apk_path = asyncio.run(fetcher.fetch(target, output_dir))
                    if apk_path:
                        self._status(f"Downloaded: {apk_path}", "green")
                    else:
                        self._status("Download failed — check if app is already installed", "yellow")
                except Exception as e:
                    self._status(f"Fetch error: {e}", "yellow")

        # ============================================================
        # STAGE 2: PREPARE
        # ============================================================
        self._stage_header(PipelineStage.PREPARE)

        # Get ADB + device
        from kahlo.device.adb import ADB, ADBError
        adb = ADB()
        try:
            devices = adb.devices()
        except ADBError as e:
            raise PipelineError(f"ADB error: {e}") from e

        if not devices:
            raise PipelineError("No devices connected")

        adb = ADB(serial=devices[0].serial)

        # Install APK if we have one
        if apk_path and not skip_fetch:
            self._status("Installing APK on device...")
            try:
                from kahlo.acquire.installer import APKInstaller
                installer = APKInstaller(adb)
                package_name = installer.install(apk_path)
                self._status(f"Installed: {package_name}", "green")
            except Exception as e:
                self._status(f"Install error: {e}", "yellow")
                if not package_name:
                    raise PipelineError(f"Cannot determine package name: {e}") from e
        elif apk_dir:
            self._status("Installing APK from directory...")
            try:
                from kahlo.acquire.installer import APKInstaller
                installer = APKInstaller(adb)
                package_name = installer.install(apk_dir)
                self._status(f"Installed: {package_name}", "green")
            except Exception as e:
                self._status(f"Install error: {e}", "yellow")
                if not package_name:
                    raise PipelineError(f"Cannot determine package name: {e}") from e

        if not package_name:
            raise PipelineError("No package name determined. Cannot proceed.")

        # Verify the package is installed
        try:
            installed_packages = adb.list_packages()
        except ADBError:
            # pm may fail without root; try via su
            try:
                output = adb.shell("pm list packages", su=True)
                installed_packages = [
                    line.replace("package:", "") for line in output.splitlines()
                    if line.startswith("package:")
                ]
            except ADBError:
                # Cannot verify — proceed anyway and let frida fail if package missing
                installed_packages = [package_name]
                self._status("Could not verify package list — proceeding anyway", "yellow")

        if package_name not in installed_packages:
            raise PipelineError(
                f"Package {package_name} is not installed on device. "
                "Install it first or remove --skip-fetch."
            )
        self._status(f"Package verified on device: {package_name}", "green")

        # Manifest analysis
        manifest_info = None
        try:
            from kahlo.prepare.manifest import ManifestAnalyzer
            analyzer = ManifestAnalyzer()
            # Try to analyze from APK path or find it on device
            if apk_path:
                manifest_info = analyzer.analyze(apk_path)
            elif apk_dir:
                manifest_info = analyzer.analyze(apk_dir)
            else:
                # Try to pull APK from device
                from kahlo.device.adb import validate_shell_arg
                validate_shell_arg(package_name, "package name")
                apk_device_path = adb.shell(f"pm path {package_name}")
                if apk_device_path and "package:" in apk_device_path:
                    device_apk = apk_device_path.split("package:")[1].strip().split("\n")[0]
                    import tempfile
                    local_apk = os.path.join(tempfile.mkdtemp(), "base.apk")
                    adb.pull(device_apk, local_apk)
                    manifest_info = analyzer.analyze(local_apk)

            if manifest_info and manifest_info.package_name:
                self._status(
                    f"Manifest: {manifest_info.package_name} v{manifest_info.version_name or '?'} "
                    f"({len(manifest_info.permissions)} permissions, "
                    f"{len(manifest_info.activities)} activities)",
                    "green",
                )
        except Exception as e:
            self._status(f"Manifest analysis: {e}", "yellow")

        # Background jadx decompilation (optional)
        jadx_proc = None
        if not skip_static and apk_path:
            try:
                from kahlo.prepare.decompiler import Decompiler
                decompiler = Decompiler()
                if decompiler.available:
                    jadx_output = os.path.join(output_dir, f"{package_name}_jadx")
                    jadx_proc = decompiler.decompile(apk_path, jadx_output)
                    self._status("jadx decompilation started (background)", "dim")
            except Exception as e:
                self._status(f"jadx error: {e}", "yellow")

        # ============================================================
        # STAGE 3: INSTRUMENT
        # ============================================================
        self._stage_header(PipelineStage.INSTRUMENT)

        from kahlo.device.frida_server import FridaServer
        from kahlo.instrument.engine import FridaEngine
        from kahlo.instrument.loader import ScriptLoader
        from kahlo.instrument.session import Session
        from kahlo.stealth.manager import StealthManager

        fs = FridaServer(adb)
        if not fs.is_running():
            self._status("Starting frida-server...")
            fs.start()
            time.sleep(1)

        stealth = StealthManager(adb, fs)
        engine = FridaEngine(stealth)

        # Compose scripts
        loader = ScriptLoader()
        bypass_scripts = ["bypass/stealth", "bypass/ssl_unpin"]
        hook_scripts = ["common", "hooks/traffic", "hooks/vault", "hooks/recon", "hooks/netmodel"]

        extra_scripts = []
        available = loader.list_scripts()
        if "discovery" in available:
            extra_scripts.append("discovery")

        script_source = loader.compose(
            bypass=bypass_scripts,
            hooks=hook_scripts + extra_scripts,
        )
        self._status(f"Script composed: {len(script_source):,} bytes")

        # Create session
        session = Session(package=package_name, output_dir=output_dir)
        if manifest_info:
            session.metadata["manifest"] = manifest_info.model_dump()

        # Spawn app
        self._status(f"Spawning {package_name}...")
        try:
            pid = engine.spawn(
                package_name,
                script_source=script_source,
                on_message=session.on_message,
            )
            self._status(f"PID: {pid}", "green")
        except Exception as e:
            raise PipelineError(f"Failed to spawn app: {e}") from e

        # Collect events
        self._status(f"Collecting events for {duration} seconds...")
        self.console.print("[dim]  Interact with the app on the device to generate traffic.[/dim]\n")

        try:
            start_time = time.time()
            with Live(console=self.console, refresh_per_second=2) as live:
                while time.time() - start_time < duration:
                    elapsed = int(time.time() - start_time)
                    remaining = duration - elapsed
                    n_events = len(session.events)

                    module_counts: dict[str, int] = {}
                    for ev in session.events:
                        mod = ev.get("module", "?")
                        module_counts[mod] = module_counts.get(mod, 0) + 1

                    counts_str = "  ".join(
                        f"[cyan]{m}[/cyan]:{c}" for m, c in sorted(module_counts.items())
                    )

                    progress_bar = "#" * (elapsed * 40 // max(duration, 1))
                    progress_empty = "-" * (40 - len(progress_bar))

                    display = (
                        f"[{progress_bar}{progress_empty}] {elapsed}s / {duration}s  "
                        f"({remaining}s remaining)\n\n"
                        f"Events: [bold green]{n_events}[/bold green]\n"
                        f"{counts_str}"
                    )
                    live.update(Panel(display, title="Scanning", border_style="blue"))
                    time.sleep(0.5)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan interrupted by user[/yellow]")

        # Cleanup frida
        self.console.print()
        self._status("Stopping instrumentation...")
        engine.cleanup()

        # Save session
        session_path = session.save()
        self._status(f"Session saved: {session_path}", "green")

        # ============================================================
        # STAGE 4: ANALYZE
        # ============================================================
        self._stage_header(PipelineStage.ANALYZE)

        events = session.events

        from kahlo.analyze.auth import analyze_auth
        from kahlo.analyze.netmodel import analyze_netmodel
        from kahlo.analyze.patterns import analyze_patterns
        from kahlo.analyze.recon import analyze_recon
        from kahlo.analyze.traffic import analyze_traffic
        from kahlo.analyze.vault import analyze_vault

        self._status("Traffic analysis...")
        traffic = analyze_traffic(events, package_name)
        self._status(f"  {len(traffic.servers)} servers, {len(traffic.endpoints)} endpoints", "green")

        self._status("Vault analysis...")
        vault = analyze_vault(events, package_name)
        self._status(f"  {len(vault.secrets)} secrets, {len(vault.prefs_files)} pref files", "green")

        self._status("Recon analysis...")
        recon = analyze_recon(events)
        self._status(f"  appetite={recon.fingerprint_appetite}/100", "green")

        self._status("Netmodel analysis...")
        netmodel = analyze_netmodel(events)
        self._status(f"  {netmodel.total_hash_ops} hashes, {len(netmodel.hmac_keys)} HMAC keys", "green")

        self._status("Pattern detection...")
        traffic_hosts = [s.host for s in traffic.servers]
        patterns = analyze_patterns(events, traffic_hosts)
        self._status(f"  {len(patterns.sdks)} SDKs detected", "green")

        self._status("Auth flow analysis...")
        auth = analyze_auth(events, package_name)
        auth_str = f"{len(auth.auth_steps)} steps"
        if auth.jwt_tokens:
            auth_str += f", {len(auth.jwt_tokens)} JWTs"
        self._status(f"  {auth_str}", "green")

        # Static analysis (from jadx output, if available)
        static_report = None
        jadx_output = os.path.join(output_dir, f"{package_name}_jadx")
        if os.path.isdir(jadx_output):
            self._status("Static code analysis (jadx output)...")
            from kahlo.analyze.static import analyze_static
            static_report = analyze_static(jadx_output)
            self._status(
                f"  {len(static_report.urls)} URLs, {len(static_report.secrets)} secrets, "
                f"{len(static_report.crypto_usage)} crypto patterns",
                "green",
            )

        # ============================================================
        # STAGE 5: REPORT
        # ============================================================
        self._stage_header(PipelineStage.REPORT)

        from kahlo.report.api_spec import generate_api_spec
        from kahlo.report.markdown import generate_markdown
        from kahlo.report.replay import generate_replay

        # Determine report directory
        report_dir = os.path.join(output_dir, f"{session.session_id}_report")
        os.makedirs(report_dir, exist_ok=True)

        # Load session data for report generation
        with open(session_path, "r", encoding="utf-8") as f:
            session_data = json.load(f)

        # Markdown report
        self._status("Generating report.md...")
        md_content = generate_markdown(
            session_data, traffic, vault, recon, netmodel, patterns,
            auth=auth, static=static_report,
        )
        md_path = os.path.join(report_dir, "report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        self._status(f"  report.md: {len(md_content):,} bytes", "green")

        # API spec
        self._status("Generating api-spec.json...")
        spec_content = generate_api_spec(session_data, traffic, vault, netmodel)
        spec_path = os.path.join(report_dir, "api-spec.json")
        with open(spec_path, "w", encoding="utf-8") as f:
            f.write(spec_content)
        self._status(f"  api-spec.json: {len(spec_content):,} bytes", "green")

        # Replay scripts
        self._status("Generating replay scripts...")
        replay_dir = os.path.join(report_dir, "replay")
        replay_files = generate_replay(replay_dir, traffic, vault, netmodel, package_name)
        self._status(f"  replay/: {len(replay_files)} files", "green")

        # Wait for jadx if still running
        if jadx_proc is not None:
            self._status("Waiting for jadx to finish...")
            try:
                jadx_proc.wait(timeout=60)
                if jadx_proc.returncode == 0:
                    self._status("jadx decompilation complete", "green")
                else:
                    self._status("jadx finished with warnings", "yellow")
            except Exception:
                jadx_proc.kill()
                self._status("jadx timed out — killed", "yellow")

        # Store session dir for reference
        self._session_dir = report_dir

        # ============================================================
        # SUMMARY
        # ============================================================
        self.console.print()
        summary = Table(title="Pipeline Summary")
        summary.add_column("Item", style="cyan")
        summary.add_column("Value", style="green")

        summary.add_row("Package", package_name)
        summary.add_row("Duration", f"{duration}s")
        summary.add_row("Events", str(len(events)))
        summary.add_row("Servers", str(len(traffic.servers)))
        summary.add_row("Endpoints", str(len(traffic.endpoints)))
        summary.add_row("Secrets", str(len(vault.secrets)))
        summary.add_row("SDKs", str(len(patterns.sdks)))
        summary.add_row("Fingerprint Appetite", f"{recon.fingerprint_appetite}/100")
        summary.add_row("", "")
        summary.add_row("Session", session_path)
        summary.add_row("Report", report_dir)

        self.console.print(summary)

        return report_dir
