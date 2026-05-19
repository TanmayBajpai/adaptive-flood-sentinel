import math
import time
import threading
from collections import deque
from config import ANOMALY_WINDOW, ANOMALY_MIN_SAMPLES, ANOMALY_STDDEV_MULT


class AnomalyDetector:
    def __init__(self):
        self._window: deque = deque()   # (timestamp, rate)
        self._lock = threading.Lock()
        self.last_z_score = 0.0

    def record(self, rate: float):
        now = time.monotonic()
        cutoff = now - ANOMALY_WINDOW
        with self._lock:
            self._window.append((now, rate))
            while self._window and self._window[0][0] < cutoff:
                self._window.popleft()

    def check(self, current_rate: float) -> tuple[bool, float]:
        with self._lock:
            samples = [r for _, r in self._window]

        if len(samples) < ANOMALY_MIN_SAMPLES:
            return False, 0.0

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        # Floor prevents division-by-zero and ensures a stable baseline (e.g.
        # all-zero idle samples) still produces a finite z-score when traffic
        # suddenly arrives.
        stddev = max(1.0, math.sqrt(variance))

        z = (current_rate - mean) / stddev
        self.last_z_score = z
        return z > ANOMALY_STDDEV_MULT, z
