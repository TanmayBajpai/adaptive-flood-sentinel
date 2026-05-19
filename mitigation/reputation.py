import os
import sqlite3
import math
import time
import threading
from config import REPUTATION_DB_PATH, REPUTATION_DECAY_LAMBDA


class ReputationDB:
    def __init__(self, path: str = REPUTATION_DB_PATH):
        self._path = path
        self._lock = threading.Lock()
        # Single long-lived connection. The per-call connect pattern was fragile
        # under sustained load — any transient FS hiccup surfaced as
        # `sqlite3.OperationalError: unable to open database file`.
        parent = os.path.dirname(self._path) or "."
        os.makedirs(parent, exist_ok=True)
        try:
            self._con = sqlite3.connect(
                self._path,
                check_same_thread=False,   # all access is serialized by self._lock
                isolation_level=None,      # autocommit; we don't need implicit txns
            )
        except sqlite3.OperationalError as e:
            raise sqlite3.OperationalError(
                f"{e} (reputation DB path: {self._path!r}, "
                f"parent writable: {os.access(parent, os.W_OK)})"
            ) from e
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._con.execute("""
                CREATE TABLE IF NOT EXISTS reputation (
                    ip       TEXT PRIMARY KEY,
                    score    REAL    NOT NULL DEFAULT 0,
                    last_seen REAL   NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                )
            """)

    def get_score(self, ip: str) -> float:
        now = time.time()
        with self._lock:
            row = self._con.execute(
                "SELECT score, last_seen FROM reputation WHERE ip = ?", (ip,)
            ).fetchone()
        if not row:
            return 0.0
        score, last_seen = row
        elapsed = now - last_seen
        return score * math.exp(-REPUTATION_DECAY_LAMBDA * elapsed)

    def update_score(self, ip: str, delta: float):
        now = time.time()
        current = self.get_score(ip)
        new_score = max(0.0, min(100.0, current + delta))
        with self._lock:
            self._con.execute("""
                INSERT INTO reputation (ip, score, last_seen, hit_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET
                    score     = excluded.score,
                    last_seen = excluded.last_seen,
                    hit_count = hit_count + 1
            """, (ip, new_score, now))

    def get_all(self) -> list:
        now = time.time()
        with self._lock:
            rows = self._con.execute(
                "SELECT ip, score, last_seen, hit_count FROM reputation"
            ).fetchall()
        result = []
        for ip, score, last_seen, hit_count in rows:
            elapsed = now - last_seen
            decayed = score * math.exp(-REPUTATION_DECAY_LAMBDA * elapsed)
            result.append({"ip": ip, "score": decayed, "hit_count": hit_count})
        return result
