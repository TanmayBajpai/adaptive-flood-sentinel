import hmac
import hashlib
import os
import time
import threading
from config import SYN_COOKIE_TIMESLOT


class SynCookieValidator:
    def __init__(self, timeslot: int = SYN_COOKIE_TIMESLOT):
        self._key = os.urandom(32)
        self._timeslot = timeslot
        self._lock = threading.Lock()
        self._events: list = []   # last 50 {ts, ip, result}
        self._issued: dict = {}   # (src_ip, src_port, dst_ip, dst_port) -> issue_time

    def _make_cookie(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, slot: int) -> int:
        msg = f"{src_ip}:{src_port}:{dst_ip}:{dst_port}:{slot}".encode()
        digest = hmac.new(self._key, msg, hashlib.sha256).digest()[:4]
        return int.from_bytes(digest, "big")

    def _current_slot(self) -> int:
        return int(time.time()) // self._timeslot

    def issue(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> int:
        slot = self._current_slot()
        with self._lock:
            self._issued[(src_ip, src_port, dst_ip, dst_port)] = time.time()
        return self._make_cookie(src_ip, src_port, dst_ip, dst_port, slot)

    def validate(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, ack_num: int) -> str:
        slot = self._current_slot()
        key = (src_ip, src_port, dst_ip, dst_port)
        cutoff = time.time() - self._timeslot * 2

        with self._lock:
            # Prune expired issued entries
            stale = [k for k, t in self._issued.items() if t < cutoff]
            for k in stale:
                del self._issued[k]
            issued = key in self._issued
            if issued:
                del self._issued[key]

        if not issued:
            self._record(src_ip, "MISS")
            return "MISS"

        result = "FAIL"
        for s in (slot, slot - 1):
            expected = self._make_cookie(src_ip, src_port, dst_ip, dst_port, s)
            if (ack_num - 1) & 0xFFFFFFFF == expected:
                result = "VALID"
                break

        self._record(src_ip, result)
        return result

    def _record(self, ip: str, result: str):
        with self._lock:
            self._events.append({"ts": time.time(), "ip": ip, "result": result})
            if len(self._events) > 50:
                self._events = self._events[-50:]

    def get_events(self) -> list:
        with self._lock:
            return list(self._events)
