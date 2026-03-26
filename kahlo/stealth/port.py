"""Random port allocation for stealth frida-server."""
from __future__ import annotations

import random


def random_port(low: int = 10000, high: int = 60000, exclude: set[int] | None = None) -> int:
    """Generate a random port, excluding known Frida ports."""
    exclude = exclude or {27042, 27043}
    while True:
        port = random.randint(low, high)
        if port not in exclude:
            return port
