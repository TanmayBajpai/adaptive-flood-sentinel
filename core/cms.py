import hashlib
import threading
import numpy as np
from config import CMS_WIDTH, CMS_DEPTH


class CountMinSketch:
    def __init__(self, width=CMS_WIDTH, depth=CMS_DEPTH):
        self.width = width
        self.depth = depth
        self._table = np.zeros((depth, width), dtype=np.int64)
        self._seeds = [(i + 1) * 2654435761 for i in range(depth)]
        self._lock = threading.Lock()

    def _hashes(self, key: str):
        key_bytes = key.encode()
        for seed in self._seeds:
            h = int(hashlib.md5(key_bytes + seed.to_bytes(8, "little")).hexdigest(), 16)
            yield h % self.width

    def add(self, key: str, count: int = 1):
        with self._lock:
            for row, col in enumerate(self._hashes(key)):
                self._table[row, col] += count

    def estimate(self, key: str) -> int:
        with self._lock:
            return int(min(self._table[row, col] for row, col in enumerate(self._hashes(key))))

    def get_snapshot(self, rows: int = 4, cols: int = 16) -> list:
        with self._lock:
            step_r = max(1, self.depth // rows)
            step_c = max(1, self.width // cols)
            sample = self._table[::step_r, ::step_c]
            sample = sample[:rows, :cols]
            return sample.tolist()

    def reset(self):
        with self._lock:
            self._table.fill(0)
