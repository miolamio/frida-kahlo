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
        console.print(f"[red]Ошибка ADB: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)
    manager = StealthManager(adb, fs)

    console.print("Запускаю frida-server в режиме stealth...")
    try:
        manager.start()
        console.print(f"[green]frida-server запущен на порту {manager.port}[/green]")
    except Exception as e:
        console.print(f"[red]Не удалось запустить: {e}[/red]")
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
        console.print(f"[red]Ошибка ADB: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)

    console.print("Останавливаю frida-server...")
    fs.stop()

    # Clean up ADB port forwards
    try:
        subprocess.run(
            ["adb", "-s", devices[0].serial, "forward", "--remove", "tcp:27042"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    console.print("[green]frida-server остановлен[/green]")


@app.command()
def scan(
    package: str = typer.Argument(help="Package name to scan"),
    duration: int = typer.Option(60, "--duration", "-d", help="Scan duration in seconds"),
    auth_capture: bool = typer.Option(False, "--auth-capture", help="Auth capture mode: clear app data, wait for login"),
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
        console.print(f"[red]Ошибка ADB: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)

    if not fs.is_running():
        console.print("Запускаю frida-server...")
        fs.start()
        time.sleep(1)

    stealth = StealthManager(adb, fs)
    engine = FridaEngine(stealth)

    # --- Auth capture mode: clear app data for fresh login ---
    if auth_capture:
        console.print(f"\n[bold yellow]РЕЖИМ ЗАХВАТА АВТОРИЗАЦИИ[/bold yellow]")
        console.print(f"Очищаю данные {package}...")
        try:
            from kahlo.device.adb import validate_shell_arg
            validate_shell_arg(package, "имя пакета")
            adb.shell(f"pm clear {package}")
            console.print(f"  [green]Данные очищены[/green]")
        except Exception as e:
            console.print(f"  [yellow]Не удалось очистить: {e}[/yellow]")
        time.sleep(1)

    # --- 2. Compose scripts ---
    loader = ScriptLoader()
    console.print(f"[cyan]Собираю скрипты для {package}...[/cyan]")

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

    console.print(f"  Размер скрипта: {len(script_source):,} байт")

    # --- 3. Create session ---
    session = Session(package=package)
    if auth_capture:
        session.metadata["auth_capture"] = True

    # --- 4. Spawn app with hooks ---
    console.print(f"[green]Запускаю {package}...[/green]")
    try:
        pid = engine.spawn(
            package,
            script_source=script_source,
            on_message=session.on_message,
        )
        console.print(f"  PID: {pid}")
    except Exception as e:
        console.print(f"[red]Не удалось запустить: {e}[/red]")
        raise typer.Exit(1)

    # --- 5. Collect events ---
    if auth_capture:
        # Auth capture mode: run until Ctrl+C
        console.print(f"\n[bold yellow]Залогиньтесь в приложение. Нажмите Ctrl+C когда закончите.[/bold yellow]")
        console.print("[dim]Авторизационные события будут подсвечены.[/dim]\n")

        try:
            start_time = time.time()
            with Live(console=console, refresh_per_second=2) as live:
                while True:
                    elapsed = int(time.time() - start_time)
                    n_events = len(session.events)

                    # Count auth events specifically
                    auth_count = sum(
                        1 for ev in session.events
                        if ev.get("data", {}).get("auth_flow")
                        or ev.get("type") in ("encrypted_pref_read", "encrypted_pref_write", "encrypted_pref_dump", "tink_decrypt")
                    )

                    module_counts = {}
                    for ev in session.events:
                        mod = ev.get("module", "?")
                        module_counts[mod] = module_counts.get(mod, 0) + 1

                    counts_str = "  ".join(
                        f"[cyan]{m}[/cyan]:{c}" for m, c in sorted(module_counts.items())
                    )

                    mins, secs = divmod(elapsed, 60)

                    display = (
                        f"[bold yellow]AUTH CAPTURE[/bold yellow]  {mins:02d}:{secs:02d}\n\n"
                        f"Events: [bold green]{n_events}[/bold green]  "
                        f"Auth events: [bold yellow]{auth_count}[/bold yellow]\n"
                        f"{counts_str}"
                    )
                    live.update(Panel(display, title="Auth Capture", border_style="yellow"))

                    time.sleep(0.5)
        except KeyboardInterrupt:
            console.print("\n[yellow]Захват авторизации остановлен[/yellow]")
    else:
        # Standard scan mode
        console.print(f"\n[bold]Собираю события {duration} секунд...[/bold]")
        console.print("[dim]Взаимодействуйте с приложением на устройстве.[/dim]\n")

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
            console.print("\n[yellow]Сканирование прервано[/yellow]")

    # --- 6. Cleanup ---
    console.print("\nОстанавливаю...")
    engine.cleanup()

    # --- 7. Save session ---
    path = session.save()
    console.print(f"\n[green]Сессия сохранена: {path}[/green]")

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

    # --- 9. Auth capture: run auth analysis and print summary ---
    if auth_capture:
        _print_auth_summary(session.events, console)


def _print_auth_summary(events: list, console_obj) -> None:
    """Print auth flow summary after auth-capture scan."""
    from kahlo.analyze.auth import analyze_auth

    auth_report = analyze_auth(events)

    if auth_report.has_auth_flow:
        console_obj.print(f"\n[bold yellow]Обнаружен поток авторизации[/bold yellow]")
        console_obj.print(f"  Шагов авторизации: {len(auth_report.auth_steps)}")
        if auth_report.auth_url:
            console_obj.print(f"  URL авторизации: {auth_report.auth_url}")
        if auth_report.auth_method:
            console_obj.print(f"  Метод: {auth_report.auth_method}")
        for step in auth_report.auth_steps:
            status = f" -> {step.response.status}" if step.response else ""
            console_obj.print(f"    [{step.step_type}] {step.request.method} {step.request.url}{status}")
    else:
        console_obj.print(f"\n[dim]Шаги авторизации не обнаружены в трафике[/dim]")

    if auth_report.jwt_tokens:
        console_obj.print(f"\n[bold yellow]JWT Tokens ({len(auth_report.jwt_tokens)})[/bold yellow]")
        for jwt in auth_report.jwt_tokens:
            expired_str = " [red]EXPIRED[/red]" if jwt.is_expired else ""
            console_obj.print(f"  Source: {jwt.source}")
            if jwt.issuer:
                console_obj.print(f"    iss: {jwt.issuer}")
            if jwt.subject:
                console_obj.print(f"    sub: {jwt.subject}")
            if jwt.expires_at:
                console_obj.print(f"    exp: {jwt.expires_at}{expired_str}")
            if jwt.custom_claims:
                for k, v in list(jwt.custom_claims.items())[:5]:
                    console_obj.print(f"    {k}: {str(v)[:80]}")

    if auth_report.encrypted_prefs:
        console_obj.print(f"\n[bold yellow]Decrypted Prefs ({len(auth_report.encrypted_prefs)})[/bold yellow]")
        for entry in auth_report.encrypted_prefs:
            val_preview = entry.value[:80] + "..." if entry.value and len(entry.value) > 80 else entry.value
            console_obj.print(f"  {entry.key} = {val_preview}")

    if auth_report.tink_decrypts > 0:
        console_obj.print(f"\n[dim]Tink decrypt operations: {auth_report.tink_decrypts}[/dim]")


@app.command()
def report(
    session_path: str = typer.Argument(help="Path to session JSON file"),
    output_dir: str = typer.Option(None, "--output", "-o", help="Output directory (default: next to session file)"),
    jadx_dir: str = typer.Option(None, "--jadx", help="Path to jadx output directory for static analysis"),
):
    """Generate analysis report from a session JSON file."""
    import json
    import os

    from kahlo.analyze.auth import analyze_auth
    from kahlo.analyze.netmodel import analyze_netmodel
    from kahlo.analyze.patterns import analyze_patterns
    from kahlo.analyze.recon import analyze_recon
    from kahlo.analyze.static import analyze_static
    from kahlo.analyze.traffic import analyze_traffic
    from kahlo.analyze.vault import analyze_vault
    from kahlo.report.api_spec import generate_api_spec
    from kahlo.report.markdown import generate_markdown
    from kahlo.report.replay import generate_replay

    # Load session
    if not os.path.exists(session_path):
        console.print(f"[red]Session file not found: {session_path}[/red]")
        raise typer.Exit(1)

    console.print(f"Loading session: [cyan]{session_path}[/cyan]")
    with open(session_path, "r", encoding="utf-8") as f:
        session = json.load(f)

    events = session.get("events", [])
    package = session.get("package", "unknown")
    session_id = session.get("session_id", "unknown")

    console.print(f"  Package: {package}")
    console.print(f"  Events: {len(events)}")

    # Determine output directory
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(session_path) or ".", f"{session_id}_report")
    os.makedirs(output_dir, exist_ok=True)

    # Run all analyzers
    console.print("\n[bold]Running analyzers...[/bold]")

    console.print("  Traffic analysis...", end="")
    traffic = analyze_traffic(events, package)
    console.print(f" [green]{len(traffic.servers)} servers, {len(traffic.endpoints)} endpoints[/green]")

    console.print("  Vault analysis...", end="")
    vault = analyze_vault(events, package)
    console.print(f" [green]{len(vault.secrets)} secrets, {len(vault.prefs_files)} pref files[/green]")

    console.print("  Recon analysis...", end="")
    recon = analyze_recon(events)
    console.print(f" [green]appetite={recon.fingerprint_appetite}/100[/green]")

    console.print("  Netmodel analysis...", end="")
    netmodel = analyze_netmodel(events)
    console.print(f" [green]{netmodel.total_hash_ops} hashes, {len(netmodel.hmac_keys)} HMAC keys[/green]")

    console.print("  Pattern detection...", end="")
    traffic_hosts = [s.host for s in traffic.servers]
    patterns = analyze_patterns(events, traffic_hosts)
    console.print(f" [green]{len(patterns.sdks)} SDKs detected[/green]")

    console.print("  Auth flow analysis...", end="")
    auth = analyze_auth(events, package)
    auth_str = f"{len(auth.auth_steps)} steps"
    if auth.jwt_tokens:
        auth_str += f", {len(auth.jwt_tokens)} JWTs"
    if auth.encrypted_prefs:
        auth_str += f", {len(auth.encrypted_prefs)} decrypted prefs"
    console.print(f" [green]{auth_str}[/green]")

    static_report = None
    if jadx_dir and os.path.isdir(jadx_dir):
        console.print("  Static analysis...", end="")
        static_report = analyze_static(jadx_dir)
        console.print(f" [green]{len(static_report.urls)} URLs, "
                      f"{len(static_report.secrets)} secrets, "
                      f"{len(static_report.crypto_usage)} crypto[/green]")

    # Generate reports
    console.print("\n[bold]Generating reports...[/bold]")

    # Markdown report
    console.print("  report.md...", end="")
    md_content = generate_markdown(session, traffic, vault, recon, netmodel, patterns, auth, static=static_report)
    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    console.print(f" [green]{len(md_content):,} bytes[/green]")

    # API spec
    console.print("  api-spec.json...", end="")
    spec_content = generate_api_spec(session, traffic, vault, netmodel)
    spec_path = os.path.join(output_dir, "api-spec.json")
    with open(spec_path, "w", encoding="utf-8") as f:
        f.write(spec_content)
    console.print(f" [green]{len(spec_content):,} bytes[/green]")

    # Replay scripts
    console.print("  replay/...", end="")
    replay_dir = os.path.join(output_dir, "replay")
    replay_files = generate_replay(replay_dir, traffic, vault, netmodel, package)
    console.print(f" [green]{len(replay_files)} files[/green]")

    # Postman collection
    console.print("  postman_collection.json...", end="")
    from kahlo.report.postman import generate_postman_collection
    postman = generate_postman_collection(traffic, vault, package)
    postman_path = os.path.join(output_dir, "postman_collection.json")
    with open(postman_path, "w", encoding="utf-8") as f:
        json.dump(postman, f, indent=2, ensure_ascii=False)
    console.print(f" [green]{os.path.getsize(postman_path):,} bytes[/green]")

    # Print summary
    console.print(f"\n[green]Reports saved to: {output_dir}[/green]")
    console.print()

    summary = Table(title="Report Summary")
    summary.add_column("Item", style="cyan")
    summary.add_column("Detail", style="green")

    summary.add_row("Servers", str(len(traffic.servers)))
    summary.add_row("Endpoints", str(len(traffic.endpoints)))
    summary.add_row("Secrets", str(len(vault.secrets)))
    summary.add_row("Pref Files", str(len(vault.prefs_files)))
    summary.add_row("SDKs", str(len(patterns.sdks)))
    summary.add_row("Hash Operations", str(netmodel.total_hash_ops))
    summary.add_row("Fingerprint Appetite", f"{recon.fingerprint_appetite}/100")
    summary.add_row("Auth Steps", str(len(auth.auth_steps)))
    summary.add_row("JWT Tokens", str(len(auth.jwt_tokens)))
    summary.add_row("Decrypted Prefs", str(len(auth.encrypted_prefs)))

    console.print(summary)

    # Print server inventory
    if traffic.servers:
        console.print("\n[cyan]Server Inventory:[/cyan]")
        for s in traffic.servers:
            console.print(f"  {s.host} ({s.ip}) - {s.role} [{s.connection_count} connections]")

    # Print detected SDKs
    if patterns.sdks:
        console.print("\n[cyan]Detected SDKs:[/cyan]")
        for sdk in patterns.sdks:
            version = f" v{sdk.version}" if sdk.version else ""
            console.print(f"  {sdk.name}{version} ({sdk.category})")


@app.command()
def monitor(
    package: str = typer.Argument(help="Package name to monitor"),
):
    """Live interactive monitoring: spawn app with hooks, display events in real time."""
    import time

    from kahlo.device.adb import ADB, ADBError
    from kahlo.device.frida_server import FridaServer
    from kahlo.instrument.engine import FridaEngine
    from kahlo.instrument.loader import ScriptLoader
    from kahlo.instrument.session import Session
    from kahlo.monitor import LiveMonitor
    from kahlo.stealth.manager import StealthManager

    # --- 1. Setup device + frida-server ---
    adb = ADB()
    try:
        devices = adb.devices()
    except ADBError as e:
        console.print(f"[red]Ошибка ADB: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)

    if not fs.is_running():
        console.print("Запускаю frida-server...")
        fs.start()
        time.sleep(1)

    stealth = StealthManager(adb, fs)
    engine = FridaEngine(stealth)

    # --- 2. Compose scripts ---
    loader = ScriptLoader()
    console.print(f"[cyan]Собираю скрипты для {package}...[/cyan]")

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

    console.print(f"  Размер скрипта: {len(script_source):,} байт")

    # --- 3. Create session + monitor ---
    session = Session(package=package)
    live_monitor = LiveMonitor(package=package, console=console)

    console.print(
        "\n[bold]Запускаю мониторинг...[/bold]"
    )
    console.print("[dim]Взаимодействуйте с приложением на устройстве. Ctrl+C для остановки.[/dim]\n")

    # --- 4. Run ---
    try:
        live_monitor.run(
            engine=engine,
            script_source=script_source,
            session=session,
        )
    except Exception as e:
        console.print(f"\n[red]Ошибка мониторинга: {e}[/red]")
        engine.cleanup()
        raise typer.Exit(1)


@app.command(name="analyze")
def analyze_cmd(
    target: str = typer.Argument(help="App name or package name (com.xxx.yyy)"),
    duration: int = typer.Option(60, "--duration", "-d", help="Scan duration in seconds"),
    skip_fetch: bool = typer.Option(False, "--skip-fetch", help="Skip APK download (assume installed)"),
    skip_static: bool = typer.Option(False, "--skip-static", help="Skip jadx decompilation"),
):
    """Full pipeline: fetch -> install -> scan -> analyze -> report."""
    from kahlo.pipeline import Pipeline, PipelineError

    pipeline = Pipeline(console=console)

    try:
        report_dir = pipeline.analyze(
            target=target,
            duration=duration,
            skip_fetch=skip_fetch,
            skip_static=skip_static,
        )
        console.print(f"\n[bold green]Анализ завершён: {report_dir}[/bold green]")
    except PipelineError as e:
        console.print(f"\n[red]Ошибка пайплайна: {e}[/red]")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Анализ прерван[/yellow]")
        raise typer.Exit(1)


@app.command(name="fetch")
def fetch_cmd(
    query: str = typer.Argument(help="App name to search for"),
    output_dir: str = typer.Option(None, "--output", "-o", help="Output directory"),
):
    """Download APK from mirror sites (APKPure, APKCombo)."""
    import asyncio

    from kahlo.acquire.fetcher import APKFetcher

    console.print(f"Ищу: [cyan]{query}[/cyan]")

    fetcher = APKFetcher()
    try:
        path = asyncio.run(fetcher.fetch(query, output_dir))
        if path:
            console.print(f"[green]Скачано: {path}[/green]")
        else:
            console.print("[red]Не удалось скачать ни из одного источника[/red]")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Ошибка загрузки: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="manifest")
def manifest_cmd(
    path: str = typer.Argument(help="Path to APK file or XAPK directory"),
):
    """Parse and display AndroidManifest.xml info."""
    from kahlo.prepare.manifest import ManifestAnalyzer

    analyzer = ManifestAnalyzer()
    info = analyzer.analyze(path)

    if not info.package_name:
        console.print("[yellow]Could not parse manifest[/yellow]")
        raise typer.Exit(1)

    table = Table(title="Manifest Info")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Package", info.package_name or "?")
    table.add_row("App Name", info.app_name or "?")
    table.add_row("Version", f"{info.version_name or '?'} ({info.version_code or '?'})")
    table.add_row("Min SDK", info.min_sdk or "?")
    table.add_row("Target SDK", info.target_sdk or "?")
    table.add_row("Permissions", str(len(info.permissions)))
    table.add_row("Activities", str(len(info.activities)))
    table.add_row("Services", str(len(info.services)))
    table.add_row("Receivers", str(len(info.receivers)))
    table.add_row("Cleartext", str(info.uses_cleartext))
    table.add_row("Debuggable", str(info.debuggable))

    console.print(table)

    if info.permissions:
        console.print(f"\n[cyan]Permissions ({len(info.permissions)}):[/cyan]")
        for p in info.permissions:
            console.print(f"  {p}")

    if info.activities:
        launcher = [a for a in info.activities if a.is_launcher]
        if launcher:
            console.print(f"\n[cyan]Launcher activity:[/cyan] {launcher[0].name}")


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
        console.print(f"[red]Ошибка ADB: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
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

    console.print(f"Проверяю обнаружение Frida для [cyan]{package}[/cyan]...")
    result = check_detection(
        package=package,
        device_id=devices[0].serial,
        use_remote=use_remote,
    )

    if result["status"] == "clean":
        console.print("[green]Не обнаружен: приложение работает с Frida[/green]")
    elif result["status"] == "crashed":
        console.print(f"[red]Вероятно обнаружен: {result.get('detail', 'приложение упало')}[/red]")
    else:
        console.print(f"[yellow]Ошибка проверки: {result.get('detail', 'неизвестно')}[/yellow]")


@app.command(name="static")
def static_cmd(
    jadx_dir: str = typer.Argument(help="Path to jadx output directory"),
):
    """Run static analysis on jadx decompiled output."""
    import os

    from kahlo.analyze.static import analyze_static

    if not os.path.isdir(jadx_dir):
        console.print(f"[red]Директория не найдена: {jadx_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"Сканирую jadx-вывод: [cyan]{jadx_dir}[/cyan]")
    report = analyze_static(jadx_dir)

    console.print(f"  Files scanned: {report.files_scanned}")
    console.print(f"  Files skipped: {report.files_skipped}")
    console.print()

    # Obfuscation
    obf = report.obfuscation
    console.print(f"[bold]Obfuscation:[/bold] {obf.level}" +
                  (f" ({obf.tool})" if obf.tool else ""))
    if obf.evidence:
        for ev in obf.evidence:
            console.print(f"  {ev}")
    console.print()

    # URLs
    if report.urls:
        console.print(f"[bold cyan]URLs found ({len(report.urls)}):[/bold cyan]")
        for u in report.urls[:50]:
            console.print(f"  {u.url}")
            console.print(f"    [dim]{u.file}:{u.line}[/dim]")
        if len(report.urls) > 50:
            console.print(f"  ... and {len(report.urls) - 50} more")
        console.print()

    # Secrets
    if report.secrets:
        console.print(f"[bold yellow]Secrets found ({len(report.secrets)}):[/bold yellow]")
        for s in report.secrets:
            console.print(f"  [{s.confidence}] {s.name}: {s.value[:40]}...")
            console.print(f"    [dim]{s.file}:{s.line} (pattern: {s.pattern[:40]})[/dim]")
        console.print()

    # Crypto
    if report.crypto_usage:
        console.print(f"[bold green]Crypto usage ({len(report.crypto_usage)}):[/bold green]")

        crypto_table = Table()
        crypto_table.add_column("Algorithm", style="cyan")
        crypto_table.add_column("Usage", style="green")
        crypto_table.add_column("File", style="dim")

        for c in report.crypto_usage:
            crypto_table.add_row(c.algorithm, c.usage, f"{c.file}:{c.line}")
        console.print(crypto_table)
        console.print()

    # Interesting classes
    if report.interesting_classes:
        console.print(f"[bold]Interesting classes ({len(report.interesting_classes)}):[/bold]")
        for cls in report.interesting_classes[:30]:
            console.print(f"  {cls}")
        if len(report.interesting_classes) > 30:
            console.print(f"  ... and {len(report.interesting_classes) - 30} more")
        console.print()

    # Summary
    summary = Table(title="Static Analysis Summary")
    summary.add_column("Item", style="cyan")
    summary.add_column("Count", justify="right", style="green")

    summary.add_row("URLs", str(len(report.urls)))
    summary.add_row("Secrets", str(len(report.secrets)))
    summary.add_row("Crypto patterns", str(len(report.crypto_usage)))
    summary.add_row("Interesting classes", str(len(report.interesting_classes)))
    summary.add_row("Obfuscation level", obf.level)

    console.print(summary)


@app.command(name="aggregate")
def aggregate_cmd(
    sessions: list[str] = typer.Argument(help="Paths to session JSON files (at least 2)"),
    output_dir: str = typer.Option(None, "--output", "-o", help="Output directory"),
):
    """Aggregate multiple sessions into a unified API map."""
    import json
    import os

    from kahlo.analyze.aggregate import (
        SessionAggregator,
        generate_aggregated_api_spec,
        generate_aggregated_markdown,
    )

    if len(sessions) < 2:
        console.print("[red]Требуется минимум 2 файла сессий[/red]")
        raise typer.Exit(1)

    for path in sessions:
        if not os.path.exists(path):
            console.print(f"[red]Файл не найден: {path}[/red]")
            raise typer.Exit(1)

    console.print(f"Агрегирую [cyan]{len(sessions)}[/cyan] сессий...")

    aggregator = SessionAggregator()
    report = aggregator.aggregate(sessions)

    # Determine output dir
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(sessions[0]) or ".", "aggregated_report")
    os.makedirs(output_dir, exist_ok=True)

    # Determine package name from first session
    package = report.sessions[0].package if report.sessions else "app"

    # Generate markdown
    md_content = generate_aggregated_markdown(report)
    md_path = os.path.join(output_dir, "aggregated_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Generate API spec
    spec_content = generate_aggregated_api_spec(report, package)
    spec_path = os.path.join(output_dir, "aggregated_api_spec.json")
    with open(spec_path, "w", encoding="utf-8") as f:
        f.write(spec_content)

    console.print(f"\n[green]Агрегированный отчёт сохранён: {output_dir}[/green]")
    console.print(f"  Sessions: {len(report.sessions)}")
    console.print(f"  Endpoints: {len(report.all_endpoints)}")
    console.print(f"  Servers: {len(report.all_servers)}")
    console.print(f"  Secrets: {len(report.all_secrets)}")
    console.print(f"  SDKs: {len(report.all_sdks)}")


@app.command(name="diff")
def diff_cmd(
    old_session: str = typer.Argument(help="Path to old session JSON"),
    new_session: str = typer.Argument(help="Path to new session JSON"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Compare two sessions to find changes."""
    import os

    from kahlo.analyze.diff import SessionDiffer, generate_diff_markdown

    for path in (old_session, new_session):
        if not os.path.exists(path):
            console.print(f"[red]Файл не найден: {path}[/red]")
            raise typer.Exit(1)

    console.print(f"Сравниваю сессии...")
    console.print(f"  Old: [cyan]{old_session}[/cyan]")
    console.print(f"  New: [cyan]{new_session}[/cyan]")

    differ = SessionDiffer()
    diff = differ.diff(old_session, new_session)

    md_content = generate_diff_markdown(diff)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(md_content)
        console.print(f"\n[green]Отчёт о различиях сохранён: {output}[/green]")
    else:
        # Print to console
        console.print()
        console.print(md_content)

    # Summary
    total_changes = (
        len(diff.new_endpoints)
        + len(diff.removed_endpoints)
        + len(diff.changed_endpoints)
        + len(diff.new_secrets)
        + len(diff.removed_secrets)
        + len(diff.new_sdks)
        + len(diff.removed_sdks)
    )
    if total_changes == 0:
        console.print("\n[green]Сессии идентичны[/green]")
    else:
        console.print(f"\n[yellow]Обнаружено изменений: {total_changes}[/yellow]")
        if diff.new_endpoints:
            console.print(f"  + {len(diff.new_endpoints)} new endpoints")
        if diff.removed_endpoints:
            console.print(f"  - {len(diff.removed_endpoints)} removed endpoints")
        if diff.changed_endpoints:
            console.print(f"  ~ {len(diff.changed_endpoints)} changed endpoints")


@app.command(name="export-postman")
def export_postman_cmd(
    session_path: str = typer.Argument(help="Path to session JSON file"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Export Postman Collection v2.1 from a session."""
    import json
    import os

    from kahlo.analyze.traffic import analyze_traffic
    from kahlo.analyze.vault import analyze_vault
    from kahlo.report.postman import generate_postman_collection

    if not os.path.exists(session_path):
        console.print(f"[red]Файл сессии не найден: {session_path}[/red]")
        raise typer.Exit(1)

    console.print(f"Загружаю сессию: [cyan]{session_path}[/cyan]")
    with open(session_path, "r", encoding="utf-8") as f:
        session = json.load(f)

    events = session.get("events", [])
    package = session.get("package", "unknown")

    traffic = analyze_traffic(events, package)
    vault = analyze_vault(events, package)

    collection = generate_postman_collection(traffic, vault, package)

    if not output:
        output = os.path.join(
            os.path.dirname(session_path) or ".",
            "postman_collection.json"
        )

    with open(output, "w", encoding="utf-8") as f:
        json.dump(collection, f, indent=2, ensure_ascii=False)

    item_count = sum(
        len(item.get("item", [item])) if "item" in item else 1
        for item in collection.get("item", [])
    )
    console.print(f"\n[green]Postman-коллекция сохранена: {output}[/green]")
    console.print(f"  Endpoints: {item_count}")
    console.print(f"  Servers: {len(collection.get('variable', []))}")


if __name__ == "__main__":
    app()
