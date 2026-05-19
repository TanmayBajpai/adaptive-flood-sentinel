import subprocess
import time
import threading
import logging
from config import FIREWALL_CHAIN, BLOCK_TTL

log = logging.getLogger(__name__)


class FirewallManager:
    def __init__(self, whitelist, dry_run: bool = False):
        self._whitelist = whitelist
        self._dry_run = dry_run
        self._blocked: dict = {}   # ip -> {expire, reason}
        self._lock = threading.Lock()
        self._running = False
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)

    def setup(self):
        if not self._dry_run:
            self._run(["iptables", "-N", FIREWALL_CHAIN])
            self._run(["iptables", "-I", "INPUT", "1", "-j", FIREWALL_CHAIN])
        self._running = True
        self._cleanup_thread.start()
        log.info("Firewall ready (dry_run=%s)", self._dry_run)

    def teardown(self):
        self._running = False
        if self._dry_run:
            return
        self._run(["iptables", "-F", FIREWALL_CHAIN])
        self._run(["iptables", "-D", "INPUT", "-j", FIREWALL_CHAIN])
        self._run(["iptables", "-X", FIREWALL_CHAIN])
        log.info("Firewall chain removed")

    def block_ip(self, ip: str, ttl: int = BLOCK_TTL, reason: str = "flood") -> bool:
        if self._whitelist.is_whitelisted(ip):
            return False
        with self._lock:
            if ip in self._blocked:
                return False
            self._blocked[ip] = {"expire": time.time() + ttl, "reason": reason, "ttl": ttl}
        if not self._dry_run:
            self._run(["iptables", "-A", FIREWALL_CHAIN, "-s", ip, "-j", "DROP"])
        log.info("BLOCK %s for %ds (%s)", ip, ttl, reason)
        return True

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._blocked:
                return False
            del self._blocked[ip]
        if not self._dry_run:
            self._run(["iptables", "-D", FIREWALL_CHAIN, "-s", ip, "-j", "DROP"])
        log.info("UNBLOCK %s", ip)
        return True

    def get_blocked(self) -> list:
        now = time.time()
        with self._lock:
            return [
                {
                    "ip": ip,
                    "reason": data["reason"],
                    "expires": int(data["expire"]),
                    "ttl_left": max(0, int(data["expire"] - now)),
                }
                for ip, data in self._blocked.items()
            ]

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def _cleanup_loop(self):
        while self._running:
            time.sleep(10)
            now = time.time()
            with self._lock:
                expired = [ip for ip, d in self._blocked.items() if now > d["expire"]]
            for ip in expired:
                self.unblock_ip(ip)

    @staticmethod
    def _run(cmd: list):
        try:
            subprocess.run(cmd, capture_output=True, check=False)
        except Exception as e:
            log.warning("iptables failed: %s", e)
