"""Decompiler — jadx wrapper for background APK decompilation."""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class DecompilerError(Exception):
    pass


class Decompiler:
    """Wraps jadx for APK decompilation (runs in background)."""

    def __init__(self, jadx_path: str = "/opt/homebrew/bin/jadx"):
        self.jadx_path = jadx_path

    @property
    def available(self) -> bool:
        """Check if jadx is available."""
        return os.path.exists(self.jadx_path)

    def decompile(
        self,
        apk_path: str,
        output_dir: str,
        threads: int = 4,
        show_bad_code: bool = True,
    ) -> subprocess.Popen:
        """Run jadx in background subprocess.

        Args:
            apk_path: Path to APK file to decompile.
            output_dir: Directory for decompiled output.
            threads: Number of jadx processing threads.
            show_bad_code: Show decompiled code even if jadx considers it bad.

        Returns:
            subprocess.Popen handle for monitoring progress.
        """
        if not self.available:
            raise DecompilerError(f"jadx not found at {self.jadx_path}")

        if not os.path.exists(apk_path):
            raise DecompilerError(f"APK not found: {apk_path}")

        os.makedirs(output_dir, exist_ok=True)

        cmd = [
            self.jadx_path,
            "-d", output_dir,
            "--threads-count", str(threads),
        ]
        if show_bad_code:
            cmd.append("--show-bad-code")
        cmd.append(apk_path)

        logger.info("Starting jadx: %s", " ".join(cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return proc
        except Exception as e:
            raise DecompilerError(f"Failed to start jadx: {e}") from e

    def decompile_sync(
        self,
        apk_path: str,
        output_dir: str,
        timeout: int = 300,
        threads: int = 4,
    ) -> bool:
        """Run jadx synchronously and wait for completion.

        Returns:
            True if decompilation succeeded.
        """
        proc = self.decompile(apk_path, output_dir, threads=threads)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            success = proc.returncode == 0
            if not success:
                logger.warning("jadx exited with code %d: %s", proc.returncode, stderr[:500])
            return success
        except subprocess.TimeoutExpired:
            proc.kill()
            logger.warning("jadx timed out after %d seconds", timeout)
            return False
