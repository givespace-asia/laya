"""Laya guardrail MCP server: shell-safety and patch-quality checks via the `noul` primitive.

Requires: pip install laya fastmcp
"""
import os
import ssl
import sys
import time
from pathlib import Path

_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"  # EKU: TLS server authentication
_CA_MAX_AGE = 7 * 86400


def _ensure_ca():
    """Point Python at a CA bundle of certifi plus the Windows ROOT trust anchors.

    TLS-intercepting antivirus (Norton, Kaspersky, corporate proxies) installs its
    root into the Windows store only. Python's ssl never reads that store, so model
    downloads from HuggingFace fail with CERTIFICATE_VERIFY_FAILED while curl works.

    Only the ROOT store is read, and only anchors Windows itself trusts for server
    auth: the intermediate ("CA") store holds AIA-cached certs that are not trust
    anchors, and promoting those would trust issuers the OS does not. The bundle is
    rebuilt weekly so revoked or rotated anchors do not linger.
    """
    if sys.platform != "win32" or "SSL_CERT_FILE" in os.environ:
        return
    bundle = Path.home() / ".claude" / "laya-ca-bundle.pem"
    if not (bundle.exists() and time.time() - bundle.stat().st_mtime < _CA_MAX_AGE):
        import certifi  # hard dependency of huggingface_hub; absence is a real error
        pems = [Path(certifi.where()).read_text()]
        pems += [ssl.DER_cert_to_PEM_cert(der)
                 for der, enc, trust in ssl.enum_certificates("ROOT")
                 if enc == "x509_asn" and (trust is True or _SERVER_AUTH in trust)]
        bundle.parent.mkdir(parents=True, exist_ok=True)
        bundle.write_text("\n".join(pems))
    os.environ["SSL_CERT_FILE"] = os.environ["REQUESTS_CA_BUNDLE"] = str(bundle)


_ensure_ca()

try:
    import laya
    from fastmcp import FastMCP
except ImportError as e:
    sys.exit(f"laya-guard: missing dependency ({e.name}). Run: pip install laya fastmcp")

mcp = FastMCP("laya-guard")

_agent = None


def agent():
    # ponytail: lazy load so the MCP server starts instantly; the ~850MB
    # checkpoint is only fetched/built on the first actual check.
    global _agent
    if _agent is None:
        _agent = laya.load(os.environ.get("LAYA_MODEL", "convaiinnovations/laya"))
    return _agent


def _noul(state, questions):
    """Score each question. Raises rather than returning a permissive default:
    a guardrail that cannot run must not look like a guardrail that passed."""
    answers = agent().predict(state, questions)["answers"]
    return {k: round(float(answers[k]["noul"]), 4) for k in questions}


@mcp.tool
def evaluate_shell_safety(command: str) -> dict:
    """Judge whether a shell command is destructive, exfiltrating, or otherwise unsafe to run."""
    scores = _noul({"command": command}, {
        "destructive": {"type": "noul", "instructions": "Does this shell command irreversibly delete, overwrite, or corrupt data, or wipe a disk, repository, or database?"},
        "exfiltration": {"type": "noul", "instructions": "Does this shell command send local data, credentials, or secrets to a remote host?"},
        "privilege": {"type": "noul", "instructions": "Does this shell command escalate privileges or change system-wide configuration, permissions, or security settings?"},
    })
    risk = max(scores.values())
    return {"command": command, "scores": scores, "risk": round(risk, 4),
            "verdict": "block" if risk >= 0.8 else "warn" if risk >= 0.5 else "allow",
            "advisory": "Laya scores intent, not syntax. An 'allow' is not proof of safety."}


@mcp.tool
def evaluate_code_quality(task_description: str, code_patch: str) -> dict:
    """Judge whether a code patch actually implements the requested task, correctly and without damage."""
    scores = _noul({"task": task_description, "patch": code_patch}, {
        "addresses_task": {"type": "noul", "instructions": "Does this patch actually implement what the task asks for?"},
        "correct": {"type": "noul", "instructions": "Is this patch free of obvious bugs, broken logic, or unhandled error cases?"},
        "no_collateral": {"type": "noul", "instructions": "Does this patch avoid deleting or breaking unrelated existing functionality?"},
    })
    ok = min(scores.values())
    return {"scores": scores, "confidence": round(ok, 4),
            "verdict": "pass" if ok >= 0.6 else "review" if ok >= 0.35 else "reject",
            "advisory": "Weaker signal than evaluate_shell_safety; treat as a warning, not a gate."}


if __name__ == "__main__":
    mcp.run()
