import time
import threading
import queue
import logging
from collections import defaultdict, deque

from scapy.all import IP, TCP, UDP, ICMP

from config import (
    SYN_RATE_THRESHOLD, UDP_RATE_THRESHOLD, ICMP_RATE_THRESHOLD,
    RATE_WINDOW, CMS_PROMOTE_THRESHOLD,
)
from core.cms import CountMinSketch
from core.entropy import EntropyEngine
from core.syn_cookie import SynCookieValidator
from core.rate_limiter import RateLimiter

log = logging.getLogger(__name__)

_THRESHOLDS = {"SYN": SYN_RATE_THRESHOLD, "UDP": UDP_RATE_THRESHOLD, "ICMP": ICMP_RATE_THRESHOLD}


class Analyzer:
    def __init__(
        self,
        event_queue: queue.Queue,
        cms: CountMinSketch,
        entropy: EntropyEngine,
        syn_cookie: SynCookieValidator,
        rate_limiter: RateLimiter,
        whitelist,
        adaptive=None,
    ):
        self._q = event_queue
        self._cms = cms
        self._entropy = entropy
        self._syn_cookie = syn_cookie
        self._limiter = rate_limiter
        self._whitelist = whitelist
        self._adaptive = adaptive
        self._lock = threading.Lock()

        # Exact per-IP sliding windows
        self._windows: dict = defaultdict(lambda: {
            "SYN": deque(), "UDP": deque(), "ICMP": deque()
        })
        # Global per-protocol windows — count every packet regardless of CMS gate.
        self._global: dict = {"SYN": deque(), "UDP": deque(), "ICMP": deque()}
        self._promoted: set = set()
        # Tracks the monotonic time of the most-recent packet for each promoted IP.
        # Used by get_top_talkers to show IPs active in the last 30 s even when
        # their per-IP rate in the 5 s RATE_WINDOW happens to be zero.
        self._last_seen: dict = {}

    def process_packet(self, pkt):
        if IP not in pkt:
            return

        src_ip: str = pkt[IP].src
        dst_ip: str = pkt[IP].dst

        if self._whitelist.is_whitelisted(src_ip):
            return

        proto = None
        dst_port = 0

        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            dst_port = pkt[TCP].dport
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            if syn and not ack:
                proto = "SYN"
                self._syn_cookie.issue(src_ip, pkt[TCP].sport, dst_ip, dst_port)
            elif ack and not syn:
                result = self._syn_cookie.validate(
                    src_ip, pkt[TCP].sport, dst_ip, dst_port, pkt[TCP].ack
                )
                # Failed cookie from a challenged IP → escalate toward BLOCK
                if result == "FAIL" and self._adaptive and self._adaptive.get_tier(src_ip) == "CHALLENGE":
                    try:
                        self._q.put_nowait({"ip": src_ip, "proto": "SYN",
                                            "rate": SYN_RATE_THRESHOLD, "type": "cookie_fail"})
                    except queue.Full:
                        pass
                return
            else:
                return
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            if dst_port == 53:
                return
            proto = "UDP"
        elif ICMP in pkt:
            if pkt[ICMP].type == 8:
                proto = "ICMP"
            else:
                return
        else:
            return

        now = time.monotonic()
        cutoff = now - RATE_WINDOW

        # ── Aggregate signals: counted for EVERY packet ────────────────
        # Entropy is the primary detector for distributed/spoofed floods, so it
        # must see all traffic — not just IPs that happen to repeat enough to
        # cross the CMS promote threshold.
        self._entropy.record_packet(src_ip, dst_port)
        with self._lock:
            gwin = self._global[proto]
            gwin.append(now)
            while gwin and gwin[0] < cutoff:
                gwin.popleft()

        # ── CMS fast-path: only do per-IP exact tracking for hot sources ──
        # Spoofed floods rarely promote any single IP — by design. Those get
        # detected via entropy + global rate above. Single-source / botnet floods
        # do promote, and fall through to per-IP scoring + adaptive tiers below.
        self._cms.add(src_ip)
        if self._cms.estimate(src_ip) < CMS_PROMOTE_THRESHOLD and src_ip not in self._promoted:
            return

        self._promoted.add(src_ip)
        self._last_seen[src_ip] = now

        # RATE_LIMIT tier: soft-drop excess packets via token bucket.
        if self._adaptive and self._adaptive.get_tier(src_ip) == "RATE_LIMIT":
            if not self._limiter.consume(src_ip, rate_limited=True):
                return

        with self._lock:
            window = self._windows[src_ip][proto]
            window.append(now)
            while window and window[0] < cutoff:
                window.popleft()
            rate = len(window) / RATE_WINDOW

        if rate > _THRESHOLDS[proto]:
            try:
                self._q.put_nowait({"ip": src_ip, "proto": proto, "rate": rate, "type": "flood"})
            except queue.Full:
                pass

    def get_top_talkers(self, n: int = 10) -> list:
        now = time.monotonic()
        rate_cutoff    = now - RATE_WINDOW
        display_cutoff = now - 30.0   # show IPs active in last 30 s
        result = []
        with self._lock:
            for ip, protos in self._windows.items():
                if self._last_seen.get(ip, 0) < display_cutoff:
                    continue
                rates = {}
                for proto, window in protos.items():
                    while window and window[0] < rate_cutoff:
                        window.popleft()
                    rates[proto] = len(window) / RATE_WINDOW
                total = sum(rates.values())
                result.append({"ip": ip, "rates": rates, "total": total})
        result.sort(key=lambda x: x["total"], reverse=True)
        return result[:n]

    def get_aggregate_pps(self) -> dict:
        now = time.monotonic()
        cutoff = now - RATE_WINDOW
        pps = {"SYN": 0.0, "UDP": 0.0, "ICMP": 0.0, "total": 0.0}
        with self._lock:
            for proto in ("SYN", "UDP", "ICMP"):
                window = self._global[proto]
                while window and window[0] < cutoff:
                    window.popleft()
                pps[proto] = len(window) / RATE_WINDOW
        pps["total"] = pps["SYN"] + pps["UDP"] + pps["ICMP"]
        return pps

    def prune_idle(self, idle_seconds: float = 60.0):
        now = time.monotonic()
        cutoff = now - idle_seconds
        with self._lock:
            stale = [
                ip for ip, protos in self._windows.items()
                if self._last_seen.get(ip, 0) < cutoff
            ]
            for ip in stale:
                del self._windows[ip]
                self._promoted.discard(ip)
                self._last_seen.pop(ip, None)
