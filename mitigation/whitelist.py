import os
import subprocess
from config import WHITELIST_FILE

_STATIC = {"127.0.0.1", "::1", "0.0.0.0"}


def _default_gateway() -> str | None:
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                idx = parts.index("via")
                return parts[idx + 1]
    except Exception:
        pass
    return None


def _load_file() -> set:
    ips: set = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
    return ips


class Whitelist:
    def __init__(self):
        self._ips: set = set(_STATIC) | _load_file()
        gw = _default_gateway()
        if gw:
            self._ips.add(gw)

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self._ips

    def add(self, ip: str):
        self._ips.add(ip)
