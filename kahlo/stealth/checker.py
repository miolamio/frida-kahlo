"""Detection checker — spawn app and verify it doesn't crash (sign of Frida detection)."""
from __future__ import annotations

import time

import frida


def _get_device(use_remote: bool = False, remote_port: int = 27042) -> frida.core.Device:
    """Get frida device handle.

    Args:
        use_remote: Use remote device via localhost (for stealth port forwarding)
        remote_port: Localhost port to connect to (default 27042 = ADB-forwarded)
    """
    if use_remote:
        mgr = frida.get_device_manager()
        return mgr.add_remote_device(f"127.0.0.1:{remote_port}")
    return frida.get_usb_device(timeout=5)


def check_detection(
    package: str,
    device_id: str | None = None,
    port: int | None = None,
    use_remote: bool = False,
    timeout: float = 3.0,
) -> dict:
    """Spawn app briefly, check if it crashes (sign of Frida detection).

    Args:
        package: Android package name to check
        device_id: ADB serial (currently unused, reserved for multi-device)
        port: frida-server port (if stealth mode, used with use_remote)
        use_remote: Connect via localhost remote device (for stealth port forwarding)
        timeout: how long to wait before checking if app survived

    Returns dict with keys:
        detected: bool | None — True if app crashed, False if survived, None on error
        status: str — "clean", "crashed", or "error"
        detail: str — optional detail message
    """
    try:
        device = _get_device(use_remote=use_remote, remote_port=port or 27042)

        pid = device.spawn([package])
        device.resume(pid)
        time.sleep(timeout)

        # Check if process still alive
        try:
            session = device.attach(pid)
            session.detach()
            device.kill(pid)
            return {"detected": False, "status": "clean"}
        except frida.ProcessNotFoundError:
            return {
                "detected": True,
                "status": "crashed",
                "detail": f"App crashed within {timeout}s — likely Frida detection",
            }

    except Exception as e:
        return {"detected": None, "status": "error", "detail": str(e)}
