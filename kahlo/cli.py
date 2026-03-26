"""Frida-Kahlo CLI."""
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="kahlo",
    help="Frida-Kahlo: Android app analysis framework",
    no_args_is_help=True,
    invoke_without_command=True,
)
console = Console()


@app.callback()
def main():
    """Frida-Kahlo: Android app analysis framework."""
    pass


@app.command()
def version():
    """Show version."""
    from kahlo import __version__
    console.print(f"frida-kahlo v{__version__}")


@app.command()
def device():
    """Show connected device status."""
    from kahlo.device.adb import ADB, ADBError
    from kahlo.device.frida_server import FridaServer

    adb = ADB()

    try:
        devices = adb.devices()
    except ADBError as e:
        console.print(f"[red]Ошибка ADB: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    # Use first device
    adb = ADB(serial=devices[0].serial)

    try:
        info = adb.get_device_info()
    except ADBError as e:
        console.print(f"[red]Не удалось получить информацию: {e}[/red]")
        raise typer.Exit(1)

    table = Table(title="Устройство")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")

    table.add_row("Serial", info.serial)
    table.add_row("Модель", info.model)
    table.add_row("Android", info.android_version)
    table.add_row("SDK", info.sdk_version)
    table.add_row("Build", info.build_id)
    table.add_row("ABI", info.abi)
    table.add_row("Root", "✓ Magisk" if info.rooted else "✗")

    console.print(table)

    # Frida server status
    fs = FridaServer(adb)
    installed = fs.is_installed()
    running = fs.is_running()

    console.print()
    console.print(f"frida-server: {'[green]установлен[/green]' if installed else '[red]не найден[/red]'}")
    console.print(f"frida-server: {'[green]запущен[/green]' if running else '[yellow]остановлен[/yellow]'}")

    # Third-party apps
    apps = adb.list_packages(third_party_only=True)
    if apps:
        console.print(f"\nУстановленные приложения ({len(apps)}):")
        for pkg in sorted(apps):
            console.print(f"  {pkg}")


@app.command()
def install(
    path: str = typer.Argument(help="Path to APK, XAPK, or directory with split APKs"),
):
    """Install APK on device."""
    import os
    from kahlo.device.adb import ADB, ADBError

    adb = ADB()
    devices = adb.devices()
    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)

    # Collect APK files
    if os.path.isdir(path):
        apks = sorted([os.path.join(path, f) for f in os.listdir(path) if f.endswith(".apk")])
    else:
        apks = [path]

    if not apks:
        console.print(f"[red]APK не найдены в {path}[/red]")
        raise typer.Exit(1)

    console.print(f"Устанавливаю {len(apks)} APK на {devices[0].serial}...")
    for apk in apks:
        console.print(f"  {os.path.basename(apk)}")

    try:
        result = adb.install(apks)
        console.print(f"[green]Установлено: {result}[/green]")
    except ADBError as e:
        console.print(f"[red]Ошибка установки: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="frida-start")
def frida_start():
    """Start frida-server with stealth (random port)."""
    from kahlo.device.adb import ADB, ADBError
    from kahlo.device.frida_server import FridaServer
    from kahlo.stealth.manager import StealthManager

    adb = ADB()

    try:
        devices = adb.devices()
    except ADBError as e:
        console.print(f"[red]ADB error: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]No devices connected[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)
    manager = StealthManager(adb, fs)

    console.print("Starting frida-server with stealth...")
    try:
        manager.start()
        console.print(f"[green]frida-server started on port {manager.port}[/green]")
    except Exception as e:
        console.print(f"[red]Failed to start: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="frida-stop")
def frida_stop():
    """Stop frida-server and clean up port forwarding."""
    import subprocess
    from kahlo.device.adb import ADB, ADBError
    from kahlo.device.frida_server import FridaServer

    adb = ADB()

    try:
        devices = adb.devices()
    except ADBError as e:
        console.print(f"[red]ADB error: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]No devices connected[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)

    console.print("Stopping frida-server...")
    fs.stop()

    # Clean up ADB port forwards
    try:
        subprocess.run(
            ["adb", "-s", devices[0].serial, "forward", "--remove", "tcp:27042"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    console.print("[green]frida-server stopped[/green]")


@app.command()
def scan(
    package: str = typer.Argument(help="Package name to scan"),
    duration: int = typer.Option(60, "--duration", "-d", help="Scan duration in seconds"),
):
    """Scan an app: spawn with stealth + hooks, collect events for N seconds."""
    import time
    from rich.live import Live
    from rich.panel import Panel

    from kahlo.device.adb import ADB, ADBError
    from kahlo.device.frida_server import FridaServer
    from kahlo.instrument.engine import FridaEngine
    from kahlo.instrument.loader import ScriptLoader
    from kahlo.instrument.session import Session
    from kahlo.stealth.manager import StealthManager

    # --- 1. Setup device + frida-server ---
    adb = ADB()
    try:
        devices = adb.devices()
    except ADBError as e:
        console.print(f"[red]ADB error: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]No devices connected[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)

    if not fs.is_running():
        console.print("Starting frida-server...")
        fs.start()
        time.sleep(1)

    stealth = StealthManager(adb, fs)
    engine = FridaEngine(stealth)

    # --- 2. Compose scripts ---
    loader = ScriptLoader()
    console.print(f"[cyan]Composing scripts for {package}...[/cyan]")

    # Build bypass list (check what exists)
    bypass_scripts = ["bypass/stealth", "bypass/ssl_unpin"]
    hook_scripts = ["common", "hooks/traffic", "hooks/vault", "hooks/recon", "hooks/netmodel"]

    # Add discovery as extra source
    extra_scripts = []
    available = loader.list_scripts()
    if "discovery" in available:
        extra_scripts.append("discovery")

    # Compose full script: common first (provides sendEvent etc.), then bypass, then hooks
    # Note: compose() puts bypass first, then hooks. We need common.js in hooks so sendEvent is available.
    script_source = loader.compose(
        bypass=bypass_scripts,
        hooks=hook_scripts + extra_scripts,
    )

    console.print(f"  Script size: {len(script_source):,} bytes")

    # --- 3. Create session ---
    session = Session(package=package)

    # --- 4. Spawn app with hooks ---
    console.print(f"[green]Spawning {package}...[/green]")
    try:
        pid = engine.spawn(
            package,
            script_source=script_source,
            on_message=session.on_message,
        )
        console.print(f"  PID: {pid}")
    except Exception as e:
        console.print(f"[red]Failed to spawn: {e}[/red]")
        raise typer.Exit(1)

    # --- 5. Collect events with live progress ---
    console.print(f"\n[bold]Collecting events for {duration} seconds...[/bold]")
    console.print("[dim]Interact with the app on the device to generate traffic.[/dim]\n")

    try:
        start_time = time.time()
        with Live(console=console, refresh_per_second=2) as live:
            while time.time() - start_time < duration:
                elapsed = int(time.time() - start_time)
                remaining = duration - elapsed
                n_events = len(session.events)

                # Build module counts for display
                module_counts = {}
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
        console.print("\n[yellow]Scan interrupted by user[/yellow]")

    # --- 6. Cleanup ---
    console.print("\nStopping...")
    engine.cleanup()

    # --- 7. Save session ---
    path = session.save()
    console.print(f"\n[green]Session saved: {path}[/green]")

    # --- 8. Print summary ---
    stats = session.event_stats()

    summary = Table(title="Scan Summary")
    summary.add_column("Module", style="cyan")
    summary.add_column("Events", justify="right", style="green")
    summary.add_column("Types", style="dim")

    for module, count in sorted(stats["by_module"].items()):
        types = stats["by_module_type"].get(module, {})
        types_str = ", ".join(f"{t}:{c}" for t, c in sorted(types.items()))
        summary.add_row(module, str(count), types_str)

    summary.add_row("", "", "")
    summary.add_row("[bold]TOTAL[/bold]", f"[bold]{stats['total']}[/bold]", "")

    console.print(summary)

    if stats["unique_endpoints"]:
        console.print(f"\n[cyan]Unique endpoints ({len(stats['unique_endpoints'])}):[/cyan]")
        for ep in stats["unique_endpoints"][:20]:
            console.print(f"  {ep}")
        if len(stats["unique_endpoints"]) > 20:
            console.print(f"  ... and {len(stats['unique_endpoints']) - 20} more")


@app.command(name="stealth-check")
def stealth_check(
    package: str = typer.Argument(help="Package name to check"),
):
    """Check if app detects Frida (spawn and see if it crashes)."""
    import subprocess
    from kahlo.device.adb import ADB, ADBError
    from kahlo.device.frida_server import FridaServer
    from kahlo.stealth.checker import check_detection

    adb = ADB()

    try:
        devices = adb.devices()
    except ADBError as e:
        console.print(f"[red]ADB error: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]No devices connected[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)

    # Determine if we need to use remote device (stealth port forwarding)
    use_remote = False
    if fs.is_running():
        try:
            fwd_cmd = ["adb", "-s", devices[0].serial, "forward", "--list"]
            fwd_result = subprocess.run(fwd_cmd, capture_output=True, text=True, timeout=5)
            for line in fwd_result.stdout.splitlines():
                if "tcp:27042" in line and devices[0].serial in line:
                    # ADB forward is active — server is on a custom stealth port
                    use_remote = True
                    break
        except Exception:
            pass
    else:
        # No frida-server running — start on default port
        fs.start()

    console.print(f"Checking Frida detection for [cyan]{package}[/cyan]...")
    result = check_detection(
        package=package,
        device_id=devices[0].serial,
        use_remote=use_remote,
    )

    if result["status"] == "clean":
        console.print("[green]No detection: app survived with Frida attached[/green]")
    elif result["status"] == "crashed":
        console.print(f"[red]Detection likely: {result.get('detail', 'app crashed')}[/red]")
    else:
        console.print(f"[yellow]Error during check: {result.get('detail', 'unknown')}[/yellow]")


if __name__ == "__main__":
    app()
