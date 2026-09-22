# laya-guard

Shell-command and code-patch guardrails for Claude Code, backed by
[Laya](https://github.com/NandhaKishorM/laya) — a non-autoregressive decision model
that returns calibrated probabilities in a single forward pass. No text generation,
so there is nothing to parse and nothing to hallucinate.

Measured latency: **~33 ms** on a T4 GPU, **~490 ms** on a CPU-only torch build.
Install a CUDA torch build if the CPU figure is too slow for your workflow.

## Install

Works on Windows, macOS and Linux with the same two commands — Claude Code runs
hooks through bash on every platform, so the plugin picks its own interpreter and
device at runtime (see [Platform support](#platform-support)).

```bash
pip install laya fastmcp
claude plugin marketplace add givespace-asia/laya
claude plugin install laya-guard@laya-guard
```

Restart Claude Code. The first check downloads the ~850 MB checkpoint from
HuggingFace; every check after that is cached.

## Platform support

| Varies by machine | How it is resolved |
|---|---|
| Interpreter name | `python` on Windows (where `python3` is usually the Microsoft Store stub pointing at a different install), `python3` elsewhere. Override with `LAYA_PYTHON`. |
| Compute device | Laya itself picks CUDA → Apple MPS → CPU, and falls back to CPU on an out-of-memory error. Nothing to configure. |
| TLS-intercepting antivirus | Windows only: a CA bundle is built from certifi plus the Windows ROOT store. Skipped entirely on macOS and Linux. |
| Detached daemon | `DETACHED_PROCESS` on Windows, `start_new_session` on POSIX. |

If the plugin must use a specific interpreter — a virtualenv, `pyenv`, conda —
export `LAYA_PYTHON=/path/to/python` before starting Claude Code.

## Automatic enforcement

Once installed, every `Bash` command is scored before it runs — no prompting required.

| Hook | What it does |
|---|---|
| `SessionStart` | Spawns a background daemon that loads the checkpoint once |
| `PreToolUse` (Bash) | Scores the command; `deny` when any aspect crosses its threshold, otherwise stays silent |

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
rm -rf / --no-preserve-root  -> destructive 0.960  block
git status                   -> destructive 0.021  allow
```

## Thresholds

The three aspects do not separate equally well, so each gets its own threshold
rather than sharing one number. Measured over 20 commands — ten taken from a real
development session, ten hostile:

| Aspect | Benign range | Hostile range | Threshold |
|---|---|---|---|
| `destructive` | 0.02 – 0.11 | 0.05 – 1.00 | 0.8 |
| `exfiltration` | 0.03 – 0.90 | 0.11 – 1.00 | **0.95** |
| `privilege` | 0.07 – 0.38 | 0.06 – 0.96 | 0.8 |

`exfiltration` is the odd one: `git push`, `curl | bash` and piping a file into an
interpreter all describe sending data somewhere, and the model scores routine dev
work at 0.86 – 0.90 — overlapping the bottom of the hostile range. A shared 0.8
gate therefore denied 4 of 10 benign commands. Per-aspect thresholds allow all ten
while still denying all ten hostile ones.

Command length is not the signal. `python aspects.py` scores `exfiltration` 0.90;
a 200-character `git add` chain scores 0.19.

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
| `LAYA_PYTHON` | `python` on Windows, `python3` elsewhere | Interpreter used for the hook and the MCP server. Point it at a venv if `laya` lives outside the default Python. |
| `LAYA_MODEL` | `convaiinnovations/laya` | Checkpoint. Use `convaiinnovations/laya-multilingual` for 100+ languages. |
| `SSL_CERT_FILE` | auto-built on Windows | Set it yourself to skip CA-bundle generation entirely. |
| `LAYA_DENY_DESTRUCTIVE` | `0.8` | Deny threshold for the `destructive` aspect. |
| `LAYA_DENY_EXFILTRATION` | `0.95` | Deny threshold for `exfiltration`. |
| `LAYA_DENY_PRIVILEGE` | `0.8` | Deny threshold for `privilege`. |
| `LAYA_DENY_AT` | unset | Sets all three at once; the per-aspect variables above still win. |
| `LAYA_FAIL_CLOSED` | unset | Block Bash when the guard is unavailable instead of allowing. |

Set them under `env` in the plugin's `.mcp.json`. Thresholds live in
`laya_mcp_server.py` — edit them directly.
