#!/usr/bin/env python3
"""
DDoS Mitigation System — entry point.
Requires root for packet capture and iptables writes.

Usage:
  sudo python main.py --interface eth0
  sudo python main.py --interface lo --no-firewall   # dry-run, safe demo
"""
import argparse
import logging
import os
import queue
import signal
import sys
import time
import threading

from config import (
    CMS_WIDTH, CMS_DEPTH, DASHBOARD_PORT,
    SYN_RATE_THRESHOLD, UDP_RATE_THRESHOLD, ICMP_RATE_THRESHOLD,
    ANOMALY_STDDEV_MULT, ENTROPY_HIGH_THRESH,
)

from core.capture import PacketCapture
from core.analyzer import Analyzer
from core.cms import CountMinSketch
from core.entropy import EntropyEngine
from core.syn_cookie import SynCookieValidator
from core.rate_limiter import RateLimiter
from core.anomaly import AnomalyDetector
from mitigation.whitelist import Whitelist
from mitigation.firewall import FirewallManager
from mitigation.reputation import ReputationDB
from mitigation.adaptive import AdaptiveMitigator
import dashboard.app as dash

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-22s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")

_PROTO_MAX = {"SYN": SYN_RATE_THRESHOLD, "UDP": UDP_RATE_THRESHOLD, "ICMP": ICMP_RATE_THRESHOLD}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DDoS Mitigation System")
    p.add_argument("--interface", "-i", default="eth0", metavar="IFACE")
    p.add_argument("--no-firewall", action="store_true",
                   help="Detection only — do not write iptables rules")
    p.add_argument("--port", type=int, default=DASHBOARD_PORT,
                   help="Dashboard port (default 5000)")
    return p.parse_args()


def main():
    args = parse_args()

    if os.geteuid() != 0:
        log.warning(
            "Not running as root. Packet capture may work via libpcap permissions, "
            "but the attack simulators require CAP_NET_RAW and WILL fail.\n"
            "  Re-run with: sudo %s main.py %s",
            sys.executable,
            " ".join(sys.argv[1:]),
        )

    # ── Build components ──────────────────────────────────────
    whitelist    = Whitelist()
    event_q: queue.Queue = queue.Queue(maxsize=10_000)
    cms          = CountMinSketch(CMS_WIDTH, CMS_DEPTH)
    entropy      = EntropyEngine()
    syn_cookie   = SynCookieValidator()
    rate_limiter = RateLimiter()
    anomaly      = AnomalyDetector()
    reputation   = ReputationDB()
    adaptive     = AdaptiveMitigator(reputation)
    firewall     = FirewallManager(whitelist, dry_run=args.no_firewall)
    analyzer     = Analyzer(event_q, cms, entropy, syn_cookie, rate_limiter, whitelist, adaptive)
    capture      = PacketCapture(analyzer.process_packet, interface=args.interface)

    dash.set_firewall(firewall)

    # ── Shutdown handler ──────────────────────────────────────
    def shutdown(sig=None, frame=None):
        log.info("Shutting down…")
        capture.stop()
        # Kill any running attack subprocess
        dash.kill_attack()
        firewall.teardown()
        log.info("Clean exit")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start subsystems ──────────────────────────────────────
    firewall.setup()
    capture.start()

    dash_thread = threading.Thread(target=dash.run, kwargs={"port": args.port}, daemon=True)
    dash_thread.start()
    log.info("Dashboard → http://localhost:%d", args.port)

    dash.log_system("CAPTURE", f"sniffer attached to {args.interface} (BPF: ip and (tcp or udp or icmp))")
    dash.log_system("FIREWALL", "iptables mitigation DISABLED — detection only"
                    if args.no_firewall else "iptables chain DDOS_MITIGATE armed")

    # ── Main stats/event loop (1 s tick) ─────────────────────
    log.info("Event loop running")
    tier_history: dict = {}   # ip -> last tier; drives the mitigation log
    anomaly_active = False     # rising-edge latch for the anomaly console line
    entropy_high = False       # rising-edge latch for high-entropy console line
    while True:
        time.sleep(1)

        # ── Global signals — computed once per tick ───────────
        agg = analyzer.get_aggregate_pps()
        anomaly.record(agg["total"])
        src_e, dst_e = entropy.compute()
        entropy_contrib = min(1.0, src_e / 8.0)
        _, z = anomaly.check(agg["total"])

        # ── Rising-edge console events for the system log ─────
        if z >= ANOMALY_STDDEV_MULT and not anomaly_active:
            anomaly_active = True
            dash.log_system("ANOMALY", f"z={z:.1f}σ distributed-flood signature ({agg['total']:.0f} pps)")
        elif z < ANOMALY_STDDEV_MULT:
            anomaly_active = False
        if src_e >= ENTROPY_HIGH_THRESH and not entropy_high:
            entropy_high = True
            dash.log_system("ENTROPY", f"H(src)={src_e:.2f} bits — many distinct sources")
        elif src_e < ENTROPY_HIGH_THRESH:
            entropy_high = False

        # ── Proactive per-tick scoring of all promoted IPs ────
        # Distributed/spoofed floods never exceed the per-IP rate threshold,
        # so no events are emitted from the analyzer. Scoring here on every
        # tick ensures those IPs get entropy + anomaly scores and appear in
        # the threat table even when no single IP is the dominant source.
        for talker in analyzer.get_top_talkers(200):
            t_ip   = talker["ip"]
            t_proto = max(talker["rates"], key=talker["rates"].get)
            t_rate  = talker["total"]
            t_norm  = min(1.0, t_rate / _PROTO_MAX.get(t_proto, 100))
            score, tier, _ = adaptive.compute_score(t_ip, t_norm, entropy_contrib, z, t_proto)
            if tier == "BLOCK":
                firewall.block_ip(t_ip, reason=f"{t_proto} flood {int(t_rate)}pps")

        # ── Event drain — single-source floods exceeding per-IP threshold ──
        # Emitted by analyzer when one IP's rate > its protocol threshold.
        # Re-scoring here uses the same global entropy + z already computed.
        budget = 200
        while budget > 0:
            try:
                ev = event_q.get_nowait()
            except queue.Empty:
                break

            ip    = ev["ip"]
            proto = ev["proto"]
            rate  = ev["rate"]
            rate_norm = min(1.0, rate / _PROTO_MAX.get(proto, 100))

            score, tier, _ = adaptive.compute_score(ip, rate_norm, entropy_contrib, z, proto)
            log.info("%-15s  %-10s  score=%-5.1f  tier=%s  %.1fpps",
                     ip, proto, score, tier, rate)

            if tier == "BLOCK":
                firewall.block_ip(ip, reason=f"{proto} flood {int(rate)}pps")

            budget -= 1

        # ── Tier-transition logging ───────────────────────────
        # One place to catch escalations/de-escalations from both scoring
        # paths above; feeds the MITIGATION LOG panel.
        for talker in adaptive.get_top_talkers(200):
            t_ip, t_tier, t_score = talker["ip"], talker["tier"], talker["score"]
            prev = tier_history.get(t_ip)
            if t_tier != prev:
                tier_history[t_ip] = t_tier
                if not (prev is None and t_tier == "MONITOR"):
                    dash.log_mitigation(t_ip, prev, t_tier, t_score)
                    if t_tier == "BLOCK":
                        dash.log_system("FIREWALL", f"BLOCK {t_ip} (score {t_score:.0f}) — iptables DROP")

        # ── Periodic pruning ──────────────────────────────────
        analyzer.prune_idle()
        rate_limiter.prune()
        adaptive.prune()
        # Forget tiers for IPs the mitigator has dropped, so a returning IP
        # logs a fresh transition rather than being silently suppressed.
        _live = {t["ip"] for t in adaptive.get_top_talkers(500)}
        for _ip in [k for k in tier_history if k not in _live]:
            del tier_history[_ip]

        # ── Dashboard state snapshot ──────────────────────────
        top_talkers = adaptive.get_top_talkers(10)
        # Merge per-IP rate data so the topology graph can size nodes by traffic volume.
        _analyzer_rates = {t["ip"]: t for t in analyzer.get_top_talkers(10)}
        for t in top_talkers:
            _ar = _analyzer_rates.get(t["ip"], {})
            t["total"] = _ar.get("total", 0.0)
            t["rates"] = _ar.get("rates", {})
        blocked       = firewall.get_blocked()
        cookie_events = syn_cookie.get_events()
        cms_snap      = cms.get_snapshot(4, 16)

        old_anomalies = dash.get_state().get("anomalies", [])
        if abs(z) > 3:
            old_anomalies = old_anomalies[-19:] + [{"z": z, "ts": time.time()}]

        dash.update_state(
            pps=agg,
            entropy={"src_prefix": src_e, "dst_port": dst_e},
            top_talkers=top_talkers,
            blocked=blocked,
            z_score=z,
            anomalies=old_anomalies,
            syn_cookie_events=cookie_events,
            cms_snapshot=cms_snap,
        )


if __name__ == "__main__":
    main()
