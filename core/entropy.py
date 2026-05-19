import math
import time
import threading
from collections import deque
from config import ENTROPY_WINDOW


class EntropyEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self._src_prefixes: deque = deque()   # (timestamp, prefix_str)
        self._dst_ports: deque = deque()       # (timestamp, port_int)
        self.src_entropy = 0.0
        self.dst_entropy = 0.0

    def record_packet(self, src_ip: str, dst_port: int):
        now = time.monotonic()
        prefix = ".".join(src_ip.split(".")[:3])
        with self._lock:
            self._src_prefixes.append((now, prefix))
            self._dst_ports.append((now, dst_port))

    @staticmethod
    def _shannon(items: list) -> float:
        if not items:
            return 0.0
        counts: dict = {}
        for item in items:
            counts[item] = counts.get(item, 0) + 1
        total = len(items)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def compute(self) -> tuple[float, float]:
        now = time.monotonic()
        cutoff = now - ENTROPY_WINDOW
        with self._lock:
            while self._src_prefixes and self._src_prefixes[0][0] < cutoff:
                self._src_prefixes.popleft()
            while self._dst_ports and self._dst_ports[0][0] < cutoff:
                self._dst_ports.popleft()
            src_vals = [p for _, p in self._src_prefixes]
            dst_vals = [p for _, p in self._dst_ports]

        self.src_entropy = self._shannon(src_vals)
        self.dst_entropy = self._shannon(dst_vals)
        return self.src_entropy, self.dst_entropy

    def get_entropy(self) -> dict:
        return {"src_prefix": self.src_entropy, "dst_port": self.dst_entropy}
