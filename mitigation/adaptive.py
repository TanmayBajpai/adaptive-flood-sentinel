import time
import threading
from config import TIER_MONITOR, TIER_RATE_LIMIT, TIER_CHALLENGE, TIER_BLOCK
from mitigation.reputation import ReputationDB

_TIER_NAMES = {
    TIER_MONITOR: "MONITOR",
    TIER_RATE_LIMIT: "RATE_LIMIT",
    TIER_CHALLENGE: "CHALLENGE",
    TIER_BLOCK: "BLOCK",
}


def _tier_val(score: float) -> int:
    if score >= TIER_BLOCK:
        return TIER_BLOCK
    if score >= TIER_CHALLENGE:
        return TIER_CHALLENGE
    if score >= TIER_RATE_LIMIT:
        return TIER_RATE_LIMIT
    return TIER_MONITOR


class AdaptiveMitigator:
    def __init__(self, reputation: ReputationDB):
        self._rep = reputation
        self._scores: dict = {}   # ip -> {score, tier, tier_val, components, last_updated, proto}
        self._lock = threading.Lock()

    def compute_score(
        self,
        ip: str,
        rate_norm: float,
        entropy_contribution: float,
        z_score: float,
        proto: str = "SYN",
    ) -> tuple[float, str, dict]:
        rep_raw = self._rep.get_score(ip)

        rate_comp = min(60.0, rate_norm * 60.0)
        entropy_comp = min(20.0, entropy_contribution * 20.0)
        anomaly_comp = min(20.0, max(0.0, z_score / 3.0) * 20.0)
        rep_comp = min(20.0, rep_raw * 0.2)

        score = min(100.0, rate_comp + entropy_comp + anomaly_comp + rep_comp)
        tier_v = _tier_val(score)
        tier_name = _TIER_NAMES[tier_v]

        components = {
            "rate": rate_comp,
            "entropy": entropy_comp,
            "anomaly": anomaly_comp,
            "reputation": rep_comp,
        }

        with self._lock:
            self._scores[ip] = {
                "score": score,
                "tier": tier_name,
                "tier_val": tier_v,
                "components": components,
                "last_updated": time.time(),
                "proto": proto,
            }

        if score >= TIER_BLOCK:
            self._rep.update_score(ip, 20.0)
        elif score >= TIER_CHALLENGE:
            self._rep.update_score(ip, 10.0)

        return score, tier_name, components

    def get_score(self, ip: str) -> float:
        with self._lock:
            return self._scores.get(ip, {}).get("score", 0.0)

    def get_tier(self, ip: str) -> str:
        with self._lock:
            return self._scores.get(ip, {}).get("tier", "MONITOR")

    def get_top_talkers(self, n: int = 10) -> list:
        now = time.time()
        with self._lock:
            active = [
                {"ip": ip, **data}
                for ip, data in self._scores.items()
                if now - data["last_updated"] < 30
            ]
        active.sort(key=lambda x: x["score"], reverse=True)
        return active[:n]

    def prune(self, idle_seconds: float = 60.0):
        now = time.time()
        with self._lock:
            stale = [ip for ip, d in self._scores.items()
                     if now - d["last_updated"] > idle_seconds]
            for ip in stale:
                del self._scores[ip]
