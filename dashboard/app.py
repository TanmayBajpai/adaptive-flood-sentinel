import json
import os
import sys
import time
import subprocess
import threading
import logging
from collections import deque

from flask import Flask, Response, render_template, request, jsonify

# Absolute path to the project root so subprocess paths are resolution-independent.
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

log = logging.getLogger(__name__)
app = Flask(__name__)

_state_lock = threading.Lock()
state: dict = {
    "pps": {"SYN": 0.0, "UDP": 0.0, "ICMP": 0.0, "total": 0.0},
    "blocked": [],
    "anomalies": [],
    "top_talkers": [],
    "entropy": {"src_prefix": 0.0, "dst_port": 0.0},
    "cms_snapshot": [],
    "syn_cookie_events": [],
    "attack_status": {"running": False, "type": None, "pid": None},
    "z_score": 0.0,
    "mitigation_log": [],
    "system_log": [],
}

_attack_proc: subprocess.Popen | None = None
_firewall_ref = None   # injected by main.py

# ── Event logs (dashboard panels) ─────────────────────────────────
# Bounded ring buffers; surfaced verbatim in the SSE state blob.
_LOG_CAP = 120
_mitigation_log: deque = deque(maxlen=_LOG_CAP)   # tier transitions / blocks
_system_log: deque = deque(maxlen=_LOG_CAP)       # pipeline / console events
_START_TIME = time.time()


def log_mitigation(ip: str, prev_tier: str | None, tier: str, score: float):
    """Record a per-IP tier transition for the MITIGATION LOG panel."""
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "ip": ip,
        "prev": prev_tier or "NEW",
        "tier": tier,
        "score": round(score),
    }
    with _state_lock:
        _mitigation_log.append(entry)
        state["mitigation_log"] = list(_mitigation_log)


def log_system(level: str, msg: str):
    """Record a pipeline/console event for the SYSTEM LOG panel."""
    entry = {"ts": time.strftime("%H:%M:%S"), "level": level.upper(), "msg": msg}
    with _state_lock:
        _system_log.append(entry)
        state["system_log"] = list(_system_log)


def set_firewall(fw):
    global _firewall_ref
    _firewall_ref = fw


def update_state(**kwargs):
    with _state_lock:
        for k, v in kwargs.items():
            state[k] = v


def get_state() -> dict:
    with _state_lock:
        return dict(state)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/stream")
def stream():
    def generate():
        while True:
            data = get_state()
            data["uptime"] = int(time.time() - _START_TIME)
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(1)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _watch_proc(proc: subprocess.Popen, attack_type: str):
    """Daemon thread: wait for the simulator subprocess to finish and clean up state."""
    global _attack_proc
    _, stderr_bytes = proc.communicate()
    code = proc.returncode
    stderr = (stderr_bytes or b"").decode(errors="replace").strip()

    if code != 0:
        if "Operation not permitted" in stderr or "PermissionError" in stderr:
            log.error(
                "Simulator '%s' crashed (exit %d) — raw socket permission denied.\n"
                "  The simulator requires CAP_NET_RAW (root). Re-run the main process with:\n"
                "    sudo %s main.py --interface lo --no-firewall",
                attack_type, code, sys.executable,
            )
        elif stderr:
            log.error("Simulator '%s' crashed (exit %d):\n%s", attack_type, code, stderr[-800:])
        else:
            log.warning("Simulator '%s' exited with code %d", attack_type, code)

    if code != 0 and stderr:
        log_system("ERROR", f"{attack_type} simulator exited ({code}): {stderr.splitlines()[-1][:80]}")
    else:
        log_system("ATTACK", f"{attack_type.upper()} flood finished")

    if _attack_proc is proc:
        _attack_proc = None
        update_state(attack_status={"running": False, "type": None, "pid": None})


@app.route("/api/attack/start", methods=["POST"])
def attack_start():
    global _attack_proc
    body = request.get_json(force=True, silent=True) or {}
    attack_type = body.get("type", "syn").lower()
    target = body.get("target", "127.0.0.1")
    rate = int(body.get("rate", 500))
    duration = int(body.get("duration", 30))

    script_map = {
        "syn":   "simulator/syn_flood.py",
        "udp":   "simulator/udp_flood.py",
        "icmp":  "simulator/icmp_flood.py",
        "mixed": "simulator/mixed_attack.py",
    }
    script = os.path.join(_BASE_DIR, script_map.get(attack_type, "simulator/syn_flood.py"))
    cmd = [sys.executable, script, "--target", target, "--rate", str(rate), "--duration", str(duration)]
    if attack_type == "syn":
        cmd.append("--with-acks")  # exercise SYN cookie validation path
        if body.get("fixed_src"):
            cmd += ["--src", "10.0.1.1"]  # single-source: populates topology + threat scores

    try:
        _attack_proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        update_state(attack_status={
            "running": True,
            "type": attack_type.upper(),
            "pid": _attack_proc.pid,
        })
        log.info("Attack started: %s pid=%d", attack_type, _attack_proc.pid)
        log_system("ATTACK", f"{attack_type.upper()} flood → {target} @ {rate}pps / {duration}s"
                   + (" (fixed-src 10.0.1.1)" if (attack_type == "syn" and body.get("fixed_src")) else ""))
        threading.Thread(target=_watch_proc, args=(_attack_proc, attack_type), daemon=True).start()
        return jsonify({"pid": _attack_proc.pid})
    except Exception as e:
        log.error("Failed to start attack: %s", e)
        log_system("ERROR", f"failed to start {attack_type} simulator: {e}")
        return jsonify({"error": str(e)}), 500


def kill_attack():
    """Terminate any running attack subprocess — safe to call outside a request context."""
    global _attack_proc
    if _attack_proc and _attack_proc.poll() is None:
        _attack_proc.terminate()
        try:
            _attack_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _attack_proc.kill()
        _attack_proc = None
    update_state(attack_status={"running": False, "type": None, "pid": None})


@app.route("/api/attack/stop", methods=["POST"])
def attack_stop():
    kill_attack()
    log_system("ATTACK", "attack stopped by operator")
    return jsonify({"status": "stopped"})


@app.route("/api/unblock", methods=["POST"])
def unblock():
    body = request.get_json(force=True, silent=True) or {}
    ip = body.get("ip")
    if _firewall_ref and ip:
        _firewall_ref.unblock_ip(ip)
        log_system("FIREWALL", f"manual unblock {ip}")
        return jsonify({"status": "unblocked", "ip": ip})
    return jsonify({"error": "missing ip or firewall not ready"}), 400


def run(port: int = 5000):
    app.run(port=port, debug=False, threaded=True, use_reloader=False)
