"""ScriptLoader — loads JS files from scripts/ directory, composes bypass + hooks.

In frida 17.x, the Java bridge is no longer automatically available in scripts.
This loader inlines the Java bridge from frida-tools so that Java.perform() works.
"""
from __future__ import annotations

import os
from pathlib import Path


class ScriptLoaderError(Exception):
    pass


# Resolve the scripts directory relative to this file
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"


def _find_java_bridge() -> str | None:
    """Find the Java bridge source from frida-tools installation.

    In frida 17.x, the Java bridge must be explicitly loaded into scripts.
    The bridge source lives in frida_tools/bridges/java.js.
    """
    try:
        import frida_tools
        bridge_path = Path(frida_tools.__file__).parent / "bridges" / "java.js"
        if bridge_path.exists():
            return bridge_path.read_text(encoding="utf-8")
    except (ImportError, OSError):
        pass
    return None


# Cache the bridge source at module load time
_JAVA_BRIDGE_SOURCE: str | None = _find_java_bridge()

# Preamble that inlines the Java bridge and makes Java globally available
_JAVA_BRIDGE_PREAMBLE = ""
if _JAVA_BRIDGE_SOURCE:
    _JAVA_BRIDGE_PREAMBLE = (
        "// === JAVA BRIDGE (frida 17.x compatibility) ===\n"
        f"{_JAVA_BRIDGE_SOURCE}\n"
        "Object.defineProperty(globalThis, 'Java', { value: bridge, enumerable: true, configurable: true });\n"
        "// === END JAVA BRIDGE ===\n"
    )


class ScriptLoader:
    """Loads and composes Frida JS scripts from the scripts/ directory."""

    def __init__(self, scripts_dir: str | Path | None = None):
        self.scripts_dir = Path(scripts_dir) if scripts_dir else _SCRIPTS_DIR

    @staticmethod
    def java_bridge_available() -> bool:
        """Check if the Java bridge source was found."""
        return _JAVA_BRIDGE_SOURCE is not None

    def load(self, names: list[str], include_java_bridge: bool = False) -> str:
        """Load one or more script files by name (without .js extension).

        Args:
            names: Script names like ["common"], ["bypass/stealth"], ["discovery"]
            include_java_bridge: If True, prepend the Java bridge preamble

        Examples:
            loader.load(["common"])  -> loads scripts/common.js
            loader.load(["bypass/stealth"])  -> loads scripts/bypass/stealth.js
        """
        parts = []

        if include_java_bridge and _JAVA_BRIDGE_PREAMBLE:
            parts.append(_JAVA_BRIDGE_PREAMBLE)

        for name in names:
            path = self.scripts_dir / f"{name}.js"
            if not path.exists():
                raise ScriptLoaderError(f"Script not found: {path}")
            parts.append(path.read_text(encoding="utf-8"))
        return "\n\n".join(parts)

    def compose(
        self,
        bypass: list[str] | None = None,
        hooks: list[str] | None = None,
        extra_source: str | None = None,
        include_java_bridge: bool = True,
    ) -> str:
        """Compose a full script from bypass scripts, hook scripts, and extra source.

        Bypass scripts are loaded first (stealth), then hooks, then any extra source.
        The Java bridge preamble is prepended by default for frida 17.x compatibility.
        """
        parts = []

        if include_java_bridge and _JAVA_BRIDGE_PREAMBLE:
            parts.append(_JAVA_BRIDGE_PREAMBLE)

        if bypass:
            parts.append("// === BYPASS LAYER ===")
            parts.append(self.load(bypass))

        if hooks:
            parts.append("// === HOOKS ===")
            parts.append(self.load(hooks))

        if extra_source:
            parts.append("// === EXTRA ===")
            parts.append(extra_source)

        return "\n\n".join(parts)

    def list_scripts(self, category: str | None = None) -> list[str]:
        """List available script names, optionally filtered by category (subdirectory)."""
        search_dir = self.scripts_dir
        if category:
            search_dir = search_dir / category

        if not search_dir.exists():
            return []

        scripts = []
        for js_file in search_dir.rglob("*.js"):
            rel = js_file.relative_to(self.scripts_dir)
            name = str(rel).replace(".js", "").replace(os.sep, "/")
            scripts.append(name)

        return sorted(scripts)
