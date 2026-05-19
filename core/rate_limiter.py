import time
import threading
from config import TOKEN_BUCKET_CAPACITY, TOKEN_BUCKET_RATE_LIMIT_FACTOR


class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, count: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
            self._last_refill = now
            if self._tokens >= count:
                self._tokens -= count
                return True
            return False


class RateLimiter:
    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}
        self._last_access: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, ip: str, rate_limited: bool = False) -> bool:
        capacity = (TOKEN_BUCKET_CAPACITY * TOKEN_BUCKET_RATE_LIMIT_FACTOR
                    if rate_limited else TOKEN_BUCKET_CAPACITY)
        rate = capacity  # refill = capacity tokens/s

        with self._lock:
            if ip not in self._buckets:
                self._buckets[ip] = TokenBucket(capacity, rate)
            self._last_access[ip] = time.monotonic()
            return self._buckets[ip].consume()

    def prune(self, idle_seconds: float = 120.0):
        now = time.monotonic()
        with self._lock:
            stale = [ip for ip, t in self._last_access.items() if now - t > idle_seconds]
            for ip in stale:
                self._buckets.pop(ip, None)
                self._last_access.pop(ip, None)
