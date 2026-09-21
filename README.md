# laya-guard

Shell-command and code-patch guardrails for Claude Code, backed by
[Laya](https://github.com/NandhaKishorM/laya) — a non-autoregressive decision model
that returns calibrated probabilities in a single forward pass. No text generation,
so there is nothing to parse and nothing to hallucinate.

Measured latency: **~33 ms** on a T4 GPU, **~490 ms** on a CPU-only torch build.
Install a CUDA torch build if the CPU figure is too slow for your workflow.

## Install

```bash
pip install laya fastmcp
claude plugin marketplace add givespace-asia/laya
claude plugin install laya-guard@laya-guard
```

Restart Claude Code. The first check downloads the ~850 MB checkpoint from
HuggingFace; every check after that is cached.

## Automatic enforcement

Once installed, every `Bash` command is scored before it runs — no prompting required.

| Hook | What it does |
|---|---|
| `SessionStart` | Spawns a background daemon that loads the checkpoint once |
| `PreToolUse` (Bash) | Scores the command; `deny` at risk >= 0.8, otherwise stays silent |

A cold process needs **~41 s** to build the checkpoint, and every hook invocation is
a fresh process — so a naive hook would add 41 s to every command. The model
therefore lives in a daemon and the hook is a stdlib-only HTTP client:

| | Measured |
|---|---|
| Daemon warm-up (once per session) | ~40 s, in the background |
| Hook overhead per Bash command | **~1.6 s** (260 ms of it is Python startup) |

The daemon binds `127.0.0.1` on a random port, requires a per-run token, and retires
after 30 minutes idle. Below the deny threshold the hook stays silent, which means the
normal permission flow still applies — **silence is not approval**.

If the daemon is still warming, the command is **allowed** and a note goes to stderr.
Set `LAYA_FAIL_CLOSED=1` to block instead, at the cost of a stalled first minute.

## Tools

| Tool | Returns |
|---|---|
| `evaluate_shell_safety(command)` | `destructive` / `exfiltration` / `privilege` scores, `risk`, verdict `allow`\|`warn`\|`block` |
| `evaluate_code_quality(task_description, code_patch)` | `addresses_task` / `correct` / `no_collateral` scores, `confidence`, verdict `pass`\|`review`\|`reject` |

```
rm -rf / --no-preserve-root  -> risk 0.960  block
git status                   -> risk 0.114  allow
```

## Known limits

- **The MCP tools are advisory; only the Bash hook enforces.** Claude decides when to
  call `evaluate_code_quality`. Shell commands are checked unconditionally by the hook.
- **Two copies of the model in RAM (~1.7 GB)** when both the MCP server and the guard
  daemon are loaded. Remove `.mcp.json` if you only want the hook.
- **`evaluate_code_quality` is noisier than `evaluate_shell_safety`.** On short task
  descriptions `addresses_task` under-reports. Treat it as a warning signal, not a gate.
- **Windows + TLS-intercepting antivirus.** The server builds a CA bundle from
  certifi plus the Windows **ROOT** store on first run, because Python's `ssl` cannot
  see it. Only anchors Windows trusts for TLS server auth are included, and the bundle
  is rebuilt weekly so revoked or rotated anchors do not linger. Set `SSL_CERT_FILE`
  yourself to skip this entirely.

## Config

Laya has no API key — the model runs locally. `HF_TOKEN` is only needed for gated
HuggingFace repos, and `convaiinnovations/laya` is public.

| Variable | Default | Purpose |
|---|---|---|
| `LAYA_MODEL` | `convaiinnovations/laya` | Checkpoint. Use `convaiinnovations/laya-multilingual` for 100+ languages. |
| `SSL_CERT_FILE` | auto-built on Windows | Set it yourself to skip CA-bundle generation entirely. |
| `LAYA_DENY_AT` | `0.8` | Risk score at which the Bash hook denies. |
| `LAYA_FAIL_CLOSED` | unset | Block Bash when the guard is unavailable instead of allowing. |

Set them under `env` in the plugin's `.mcp.json`. Thresholds live in
`laya_mcp_server.py` — edit them directly.
