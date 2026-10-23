"""Minimal stand-in for the Engine's `engine/db.py`: only what gatekeeper.py uses.

The real module holds the whole Engine schema; here we keep the two tables the gatekeeper touches
(`approvals` and the audit `log`) with the same columns, so gatekeeper.py runs unchanged.
"""
import os
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(os.environ.get("GATEKEEPER_DB", "~/.local/state/agent-gatekeeper/gatekeeper.db")).expanduser()

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY,
    request TEXT NOT NULL,
    reason TEXT DEFAULT '',
    cost_eur REAL DEFAULT 0,
    category TEXT DEFAULT 'action',
    status TEXT DEFAULT 'pending',           -- pending | approved | denied | answered | expired
    created TEXT, decided TEXT,
    nonce TEXT DEFAULT '',
    options TEXT DEFAULT '',
    answer TEXT DEFAULT '',
    task_id INTEGER
);
CREATE TABLE IF NOT EXISTS log (
    id INTEGER PRIMARY KEY,
    ts TEXT, actor TEXT, action TEXT, detail TEXT
);
"""


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    path = Path(path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


def log(con, actor: str, action: str, detail: str = "") -> None:
    con.execute("INSERT INTO log(ts, actor, action, detail) VALUES (?,?,?,?)", (now(), actor, action, detail))


def insert(con, table: str, **fields) -> int:
    if table == "approvals":
        fields.setdefault("created", now())
    cols = ", ".join(fields)
    marks = ", ".join("?" for _ in fields)
    return con.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", tuple(fields.values())).lastrowid
