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
claude plugin marketplace add GITHUB_OWNER/laya-guard
claude plugin install laya-guard@laya-guard
```

Restart Claude Code. The first check downloads the ~850 MB checkpoint from
HuggingFace; every check after that is cached.

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

- **Advisory, not enforcing.** Claude decides when to call these tools; they do not
  intercept every Bash call. Add a `PreToolUse` hook if you need hard enforcement.
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

Set them under `env` in the plugin's `.mcp.json`. Thresholds live in
`laya_mcp_server.py` — edit them directly.
