# Agent Gatekeeper

A policy hook that sits between autonomous coding agents (Claude Code) and my Raspberry Pi. Every
tool call an agent wants to make — a shell command, a file edit, a web fetch — is checked against
a rule set *before* it runs, and is allowed, denied, deferred, or sent to my phone for approval.

It is the security layer of my personal agent system (the "Engine", now part of the
[Unconventional-Reasoning-Atlas](https://github.com/Djeddozo/Unconventional-Reasoning-Atlas)
repository, file `engine/gatekeeper.py`). This repository packages it on its own so the security
design can be read, run and tested in isolation.

## The problem

I let coding agents run on the Pi in auto mode, often unattended for hours (a dev loop picks
tasks, builds, tests and opens pull requests). Two things had to be true at once:

1. I should **not** have to answer terminal permission prompts — otherwise autonomy is pointless.
2. Some actions must be **impossible** for an agent no matter how it reasons: touching secrets,
   privileged or destructive commands, piping remote code into a shell, rewriting published Git
   history, publishing or merging code, and editing the system's own live configuration and memory.

## How it works

```text
Claude Code wants to run a tool
        │  PreToolUse hook: JSON {tool_name, tool_input} on stdin
        ▼
 gatekeeper.decide(tool, args)                         (pure function, rules from TOML)
   1. Edit/Write outside the workspace ─────────────► deny
   2. any deny rule matches ────────────────────────► deny   (reason shown to the agent)
   3. any allow rule matches ───────────────────────► allow
   4. otherwise ("ask")
        ├─ unknown = "defer" → no output: Claude Code's own permission mode decides
        │                      (in auto mode its classifier model reviews the action)
        └─ unknown = "phone" → approval row + ntfy push with Approve / Deny buttons
                               → reply carries a one-time nonce → hook waits (600 s)
                               → no answer: on_timeout = "deny"
        ▼
 every decision is written to the audit log
```

- **Deny before allow.** A command that matches both (e.g. `cat .env`) is denied.
- **Allow rules are anchored and refuse chaining.** The "safe inspection" rule only matches when
  the *whole* command is one known-safe program without `; & | `` ` `` or `$` — so
  `git status; anything` does not ride on it and falls through to review.
- **Rename-proof.** When the CLI was renamed (`hq.sh` → `atlas.sh`), deny rules are also checked
  against the command rewritten to the old names, so a rename cannot silently disable a rule —
  and the rewrite is never used for allow rules.
- **Phone approvals cannot be forged by guessing.** Each approval carries a random
  `secrets.token_urlsafe` nonce; a reply is applied only if the nonce matches, the request is still
  pending, and only once. The Pi *polls* a private ntfy reply topic, so no inbound port is opened.
- **Two layers.** The rule set handles the cases that must be absolute; everything else is left to
  Claude Code's own auto-mode classifier rather than to me. Conceptual decisions (direction, money,
  anything external) are asked explicitly by agents with one button per option.
- **The gatekeeper never widens its own rules**, and its configuration directory is itself on the
  deny list for agents.

The deployed rules are in [`rules/gatekeeper.toml`](rules/gatekeeper.toml).

## Evidence that it works

- [`tests/test_gatekeeper.py`](tests/test_gatekeeper.py) runs the unmodified `gatekeeper.py`
  against the deployed rules: 17 behavioural tests (deny / allow / defer, chaining, rename
  aliases, nonce protocol, the JSON contract with Claude Code) plus one documented known gap.
- It is live on my Pi as a global Claude Code hook. While this very repository was being prepared
  by an agent, the gatekeeper refused the agent's `git push` ("agents commit only … Djeddi
  merges") and its attempts to create dotenv-named files — so I published it myself.

## Limitations (honest threat model)

This is a guard rail against mistakes and over-eager agents, not a sandbox against an adversary.

- **It matches command text, not effects.** A regex sees the string the agent submits. Indirection
  (writing a script and running it, an interpreter one-liner, another tool that performs the same
  operation) can reach the same effect without matching. The second layer (Claude Code's
  classifier), OS permissions, and credentials scoped to what the agent may do are what cover this.
- **False positives.** The secrets rule matches `\.env\b`, so harmless text such as
  `process.env.PORT` or a placeholder `.env.example` is refused too. Safe by default, but it costs
  agents time.
- **Known gap:** the `dd if=` alternative ends in `\b`, so `dd if=/dev/...` is not denied (it falls
  through to review). Captured as an expected-failure test.

## Run it

Python 3.11+, standard library only.

```bash
python3 -m unittest -v                                  # the test suite
python3 -m gatekeeper check Bash "git push origin main" # one policy decision
```

As a Claude Code hook (`~/.claude/settings.json`):

```json
{"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
  {"type": "command", "command": "cd /path/to/agent-gatekeeper && python3 -m gatekeeper"}]}]}}
```

Optional phone approvals: set `unknown = "phone"` in the rules and `HQ_NTFY_TOPIC` (a long random
topic name) in the hook's environment. The approval database defaults to
`~/.local/state/agent-gatekeeper/gatekeeper.db` (`GATEKEEPER_DB` overrides it).

## Files

| Path | What |
|---|---|
| `gatekeeper/gatekeeper.py` | The gatekeeper, byte-identical to `engine/gatekeeper.py` in the Engine |
| `gatekeeper/db.py`, `gatekeeper/loop.py` | Minimal stand-ins for the two Engine modules it imports (approvals table, audit log, rule loading) |
| `rules/gatekeeper.toml` | The deployed rules (shared + Pi-only file combined) |
| `tests/` | Behavioural tests |

## My role

I designed the policy model (deny-first absolute rules, defer to the classifier, phone approval
with nonces, agents-commit-only workflow) and run it daily. The code was written together with
Claude Code, as the co-author trailers in the Engine's history show.

## Next steps

- Fix the `dd` pattern and add a regression test in the Engine itself.
- Reduce false positives of the secrets rule (match paths and file arguments, not any substring).
- Log-based report of what was denied/deferred per week.
