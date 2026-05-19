#!/usr/bin/env python3
"""SYN flood simulator — spoofed src IPs from 10.0.0.0/16 (256 /24 prefixes)."""
import argparse
import random
import time
import signal
import sys

from scapy.all import IP, TCP, send, RandShort

_running = True


def _stop(sig, frame):
    global _running
    _running = False


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target",    default="127.0.0.1")
    p.add_argument("--port",      type=int, default=80)
    p.add_argument("--rate",      type=int, default=500, help="packets per second")
    p.add_argument("--duration",  type=int, default=30,  help="seconds (0=infinite)")
    p.add_argument("--src",       default=None,
                   help="fixed source IP for single-source mode (omit for distributed)")
    p.add_argument("--with-acks", action="store_true",
                   help="also send an ACK after each SYN (exercises SYN cookie validation)")
    return p.parse_args()


def rand_ip():
    # 10.0.{0-255}.{1-254}: 256 /24 prefixes × 254 hosts = ~65k unique IPs.
    # Small enough that individual IPs repeat often enough to cross CMS promote,
    # large enough for /24 prefix entropy to saturate log2(256) = 8 bits.
    return f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"


def main():
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    args = parse_args()
    interval = 1.0 / max(1, args.rate)
    deadline = time.time() + args.duration if args.duration > 0 else float("inf")
    fixed_src = args.src  # None → distributed (random IPs), else single source

    mode = f"single-source src={fixed_src}" if fixed_src else "distributed"
    ack_suffix = " +ACKs" if args.with_acks else ""
    print(f"[SYN] target={args.target}:{args.port}  rate={args.rate}pps  "
          f"duration={args.duration}s  mode={mode}{ack_suffix}")
    sent = 0

    while _running and time.time() < deadline:
        src = fixed_src if fixed_src else rand_ip()
        sport = random.randint(1024, 65535)
        syn_pkt = IP(src=src, dst=args.target) / TCP(sport=sport,
                                                      dport=args.port, flags="S")
        send(syn_pkt, verbose=False)
        sent += 1

        if args.with_acks:
            # Send a bogus ACK with a random ack number — will be logged as FAIL/MISS
            # by the SYN cookie validator, exercising the cookie event path.
            ack_pkt = IP(src=src, dst=args.target) / TCP(
                sport=sport, dport=args.port, flags="A",
                ack=random.randint(1, 0xFFFFFFFF),
            )
            send(ack_pkt, verbose=False)

        time.sleep(interval)

    print(f"[SYN] done — sent {sent} SYN packets")


if __name__ == "__main__":
    main()
