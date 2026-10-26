"""The evidence log: what separates this from a chatbot that guesses (Part 2).

Every tool call the agent makes is logged to SQLite with an evidence ID (E1,
E2, ...), the DLL's SHA-256, the tool name and arguments, a hash of the result,
the result itself, and a timestamp. The agent is asked to cite these IDs, and
the report validator refuses any "observed" claim whose cited evidence does not
actually contain the API or address named.

Pure stdlib (sqlite3, hashlib, json), so it runs anywhere and is unit-tested.
"""
import hashlib
import json
import sqlite3
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    eid        TEXT PRIMARY KEY,
    sha256     TEXT NOT NULL,
    tool       TEXT NOT NULL,
    args       TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    result     TEXT NOT NULL,
    ts         REAL NOT NULL
);
"""


class EvidenceLog:
    """A per-investigation SQLite log of tool calls, each with an E-id."""

    def __init__(self, db_path: str = ":memory:", sha256: str = ""):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(_SCHEMA)
        self.sha256 = sha256
        self._n = self.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def record(self, tool: str, args: dict, result) -> str:
        """Store one tool call and return its evidence ID (e.g. 'E3')."""
        self._n += 1
        eid = f"E{self._n}"
        blob = json.dumps(result, default=str)
        self.conn.execute(
            "INSERT INTO evidence VALUES (?,?,?,?,?,?,?)",
            (eid, self.sha256, tool, json.dumps(args, default=str),
             hashlib.sha256(blob.encode()).hexdigest(), blob, time.time()))
        self.conn.commit()
        return eid

    def get(self, eid: str) -> dict | None:
        row = self.conn.execute(
            "SELECT eid, sha256, tool, args, result FROM evidence WHERE eid=?", (eid,)).fetchone()
        if not row:
            return None
        return {"eid": row[0], "sha256": row[1], "tool": row[2],
                "args": json.loads(row[3]), "result": json.loads(row[4])}

    def exists(self, eid: str) -> bool:
        return self.get(eid) is not None

    def supports(self, eid: str, needle: str) -> bool:
        """True if ``needle`` (an API name or address) appears in that evidence's result."""
        row = self.conn.execute("SELECT result FROM evidence WHERE eid=?", (eid,)).fetchone()
        return bool(row) and needle.lower() in row[0].lower()

    def all(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT eid, tool, args, result, ts FROM evidence ORDER BY ts").fetchall()
        return [{"eid": r[0], "tool": r[1], "args": json.loads(r[2]),
                 "result": json.loads(r[3]), "ts": r[4]} for r in rows]

    def close(self):
        self.conn.close()
