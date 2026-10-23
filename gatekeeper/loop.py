"""Minimal stand-in for the Engine's `engine/loop.py`: loads the rules file.

Same merge semantics as the Engine: a second, machine-local file can add rules on top of the
shared ones (tables merge, lists of rule tables are appended, values replace).
"""
import os
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSTITUTION = Path(os.environ.get("GATEKEEPER_RULES", ROOT / "rules" / "gatekeeper.toml"))
LOCAL = Path(os.environ.get("GATEKEEPER_LOCAL_RULES", ROOT / "rules" / "local.toml"))


def merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list) and all(isinstance(x, dict) for x in v):
            out[k] = out[k] + v
        else:
            out[k] = v
    return out


def load_constitution() -> dict:
    with open(CONSTITUTION, "rb") as f:
        rules = tomllib.load(f)
    if LOCAL.exists():
        with open(LOCAL, "rb") as f:
            rules = merge(rules, tomllib.load(f))
    return rules
