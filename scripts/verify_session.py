#!/usr/bin/env python3
"""
Read-only verifier for Antigravity IDE / Desktop / CLI SQLite conversation databases.
Checks:
- Both ~/.gemini/antigravity/conversations/<cid>.db and ~/.gemini/antigravity-cli/conversations/<cid>.db
- Latest turn (and idx=0) gen_metadata ChatStartMetadata.ContextWindowMetadata.max_context_tokens:
  the checkpoint budget this patch sets, 734000 (900000 / 983040 on older patches)
- Latest turn (and idx=0) executor_metadata Config.max_token_limit when present (live sessions may omit executor_metadata rows)
Both sides (when present) must be one of ACCEPTED_LIMITS; 256000 stays LIMITED_256K.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import shutil
from contextlib import contextmanager
from pathlib import Path

# Checkpoint budget written by the patch (734000 = 0.70 * 1M), or older 900K / 983040 patched ceilings.
ACCEPTED_LIMITS = (734000, 900000, 983040)


def read_varint(b: bytes, p: int):
    v = 0
    for index in range(10):
        if p >= len(b):
            raise ValueError("Truncated protobuf varint")
        x = b[p]
        p += 1
        if index == 9 and x > 1:
            raise ValueError("Protobuf varint exceeds uint64")
        v |= (x & 127) << (index * 7)
        if x < 128:
            return v, p
    raise ValueError("Invalid protobuf varint")


def iter_fields(b: bytes):
    p = 0
    while p < len(b):
        t, p = read_varint(b, p)
        if not 1 <= t >> 3 <= 0x1FFFFFFF:
            raise ValueError("Invalid protobuf field number")
        w = t & 7
        if w == 0:
            v, p = read_varint(b, p)
        elif w == 2:
            n, p = read_varint(b, p)
            if n > len(b) - p:
                raise ValueError("Truncated protobuf length-delimited field")
            v = b[p : p + n]
            p += n
        elif w in (1, 5):
            n = 8 if w == 1 else 4
            if n > len(b) - p:
                raise ValueError("Truncated protobuf fixed-width field")
            v = b[p : p + n]
            p += n
        else:
            raise ValueError(f"Unsupported wire type: {w}")
        yield t >> 3, w, v


def get_field(b: bytes, k: int, wire=2):
    # Consume the entire message so malformed trailing fields cannot pass validation.
    fields = list(iter_fields(b))
    values = [(w, v) for f, w, v in fields if f == k]
    if not values:
        raise ValueError(f"Missing protobuf field {k}")
    if any(w != wire for w, _ in values):
        raise ValueError(f"Unexpected wire type for protobuf field {k}")
    return values[-1][1]


def conversation_dirs():
    return [
        Path.home() / ".gemini" / "antigravity" / "conversations",
        Path.home() / ".gemini" / "antigravity-cli" / "conversations",
    ]


def database_activity(path):
    """Include uncheckpointed request writes when selecting a recent session."""
    times = [path.stat().st_mtime]
    try:
        times.append(Path(str(path) + "-wal").stat().st_mtime)
    except FileNotFoundError:
        pass
    return max(times)


def find_conversation_db(cid: str | None) -> Path:
    dirs = conversation_dirs()
    if cid:
        for d in dirs:
            cand = d / f"{cid}.db"
            if cand.exists():
                return cand
        raise SystemExit(f"Database for conversation {cid} not found in {dirs}")

    all_dbs = []
    for d in dirs:
        if d.exists():
            all_dbs.extend(d.glob("*.db"))
    if not all_dbs:
        raise SystemExit(f"No conversation .db files found in {dirs}")
    return max(all_dbs, key=database_activity)


def parse_gen_usage(g: bytes):
    chat = get_field(g, 1)
    chat_fields = list(iter_fields(chat))
    window_parents = [(w, v) for f, w, v in chat_fields if f == 9]
    if not window_parents:
        raise ValueError("Missing protobuf field 9")
    if any(w != 2 for w, _ in window_parents):
        raise ValueError("Unexpected wire type for protobuf field 9")
    window = get_field(window_parents[-1][1], 10)
    gen_limit = get_field(window, 4, wire=0)
    used_vals = [(w, v) for f, w, v in iter_fields(window) if f == 1]
    if any(w != 0 for w, _ in used_vals):
        raise ValueError("Unexpected wire type for protobuf field 1")
    gen_used = used_vals[-1][1] if used_vals else None
    model_id_vals = [(w, v) for f, w, v in chat_fields if f == 3]
    if any(w != 0 for w, _ in model_id_vals):
        raise ValueError("Unexpected wire type for protobuf field 3")
    model_name_vals = [(w, v) for f, w, v in chat_fields if f == 19]
    if any(w != 2 for w, _ in model_name_vals):
        raise ValueError("Unexpected wire type for protobuf field 19")
    model_info = (
        model_id_vals[-1][1] if model_id_vals else None,
        model_name_vals[-1][1].decode("utf-8", errors="replace") if model_name_vals else None,
    )
    return chat, gen_limit, gen_used, model_info


def parse_gen_row(g: bytes):
    chat, gen_limit, _, _ = parse_gen_usage(g)
    return chat, gen_limit


def get_project_folder(conn) -> str | None:
    import urllib.parse
    try:
        row = conn.execute("select data from trajectory_metadata_blob where id='main' limit 1").fetchone()
        if not row or not row[0]:
            return None
        ws = get_field(row[0], 1, 2)
        uri_bytes = get_field(ws, 1, 2)
        uri = urllib.parse.unquote(uri_bytes.decode("utf-8", errors="replace"))
        if uri.startswith("file:///"):
            uri = uri[8:]
        elif uri.startswith("file://"):
            uri = uri[7:]
        return Path(uri.rstrip("/\\")).name or uri
    except Exception:
        return None


def get_conversation_preview(db_path: Path, conn=None) -> str | None:
    import itertools
    import re
    cid = db_path.stem
    app_dir = db_path.parent.parent
    t_path = app_dir / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
    if t_path.is_file():
        try:
            with t_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in itertools.islice(handle, 30):
                    if len(line) > 262144:
                        continue
                    obj = json.loads(line)
                    if obj.get("type") == "USER_INPUT" and obj.get("content"):
                        txt = str(obj["content"])
                        m = re.search(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", txt, re.S)
                        first_line = (m.group(1) if m else txt).strip().splitlines()
                        if first_line:
                            s = first_line[0].strip()
                            return s[:38] + (".." if len(s) > 38 else "")
        except Exception:
            pass
    if conn is not None:
        try:
            row = conn.execute("select step_payload from steps order by idx asc limit 1").fetchone()
            if row and row[0]:
                txt = row[0].decode("utf-8", errors="replace")
                m = re.search(r"sender=([0-9a-f]{8})[0-9a-f-]*\s+priority=\S+\s+content=([^\r\n]+)", txt)
                if m:
                    s = f"[Subagent<-{m.group(1)}] {m.group(2).strip()}"
                    return s[:38] + (".." if len(s) > 38 else "")
                m2 = re.search(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", txt, re.S)
                if m2:
                    first_line = m2.group(1).strip().splitlines()
                    if first_line:
                        s = first_line[0].strip()
                        return s[:38] + (".." if len(s) > 38 else "")
        except Exception:
            pass
    return None


def parse_exec_row(e: bytes):
    return get_field(get_field(get_field(e, 10), 2), 5, wire=0)


@contextmanager
def open_session_db(db_path):
    conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        conn.execute("select name from sqlite_master limit 1").fetchone()
    except sqlite3.OperationalError:
        conn.close()
        # Some read-only directories cannot supply SQLite's shared-memory files.
        # Only copy a stable standalone database; never ignore a WAL.
        if any(Path(str(db_path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise
        before = db_path.stat()
        with tempfile.TemporaryDirectory(prefix="agy-db-read-") as folder:
            copy = Path(folder) / "session.db"
            shutil.copyfile(db_path, copy)
            after = db_path.stat()
            if ((before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_ino, after.st_size, after.st_mtime_ns) or
                    any(Path(str(db_path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal"))):
                raise RuntimeError("Session DB changed during snapshot; retry or close the IDE")
            conn = sqlite3.connect(copy.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                yield conn, "stable_standalone_copy"
            finally:
                conn.close()
        return
    try:
        yield conn, "read_only"
    finally:
        conn.close()


def inspect_session(conversation_id=None, expected_limit=None, db_path=None):
    db_path = db_path.expanduser().resolve() if db_path else find_conversation_db(conversation_id)
    with open_session_db(db_path) as (conn, read_mode):
        conn.execute("BEGIN")
        if not conn.execute("select 1 from gen_metadata limit 1").fetchone():
            raise ValueError("Session has no request metadata yet")
        g_first_idx, g_first = conn.execute("select idx, data from gen_metadata order by idx asc limit 1").fetchone()
        g_last_idx, g_last = conn.execute("select idx, data from gen_metadata order by idx desc limit 1").fetchone()
        _, gen_limit_first, gen_used_first, _ = parse_gen_usage(g_first)
        _, gen_limit_last, gen_used_last, (model_id_last, model_name_last) = parse_gen_usage(g_last)

        e_rows = conn.execute(
            "select idx, data from executor_metadata where idx in "
            "((select min(idx) from executor_metadata), (select max(idx) from executor_metadata)) "
            "order by idx asc"
        ).fetchall()
        if e_rows:
            e_first_idx, e_first = e_rows[0]
            e_last_idx, e_last = e_rows[-1]
            exec_limit_first = parse_exec_row(e_first)
            exec_limit_last = parse_exec_row(e_last)
            has_executor = True
        else:
            has_executor = False
        project_folder = get_project_folder(conn)
        preview = get_conversation_preview(db_path, conn=conn)

    first_turn = {
        "gen_idx": g_first_idx,
        "gen_max_context_tokens": gen_limit_first,
    }
    if has_executor:
        first_turn["executor_idx"] = e_first_idx
        first_turn["executor_max_token_limit"] = exec_limit_first
    if gen_used_first is not None:
        first_turn["gen_used_tokens"] = gen_used_first

    latest_turn = {
        "gen_idx": g_last_idx,
        "gen_max_context_tokens": gen_limit_last,
    }
    if has_executor:
        latest_turn["executor_idx"] = e_last_idx
        latest_turn["executor_max_token_limit"] = exec_limit_last
    else:
        exec_limit_last = None
    if gen_used_last is not None:
        latest_turn["gen_used_tokens"] = gen_used_last
        if gen_limit_last:
            latest_turn["gen_usage_percent"] = round(gen_used_last / gen_limit_last * 100.0, 1)
    if model_id_last is not None:
        latest_turn["model_id"] = model_id_last
    if model_name_last:
        latest_turn["model_name"] = model_name_last

    exec_ok = (exec_limit_last is None) or (exec_limit_last in ACCEPTED_LIMITS)
    report = {
        "read_mode": read_mode,
        "db_path": str(db_path),
        "conversation_id": db_path.stem,
        "first_turn": first_turn,
        "latest_turn": latest_turn,
        "expected_limit": 734000 if expected_limit is None else expected_limit,
        "latest_limit_ok": (
            gen_limit_last in ACCEPTED_LIMITS and exec_ok
            if expected_limit is None
            else (gen_limit_last == expected_limit and exec_ok)
        ),
    }
    if project_folder:
        report["project"] = project_folder
    if preview:
        report["preview"] = preview
    return report


def main():
    ap = argparse.ArgumentParser(description="Read actual request context window from the session DB.")
    ap.add_argument("conversation_id", nargs="?", help="Conversation UUID (omit to inspect the newest .db automatically)")
    ap.add_argument("--db", type=Path, help="Read an explicit conversation database")
    ap.add_argument("--expected-limit", type=int, default=None, help="Expected max_context_tokens (default: 734000, 900000 or 983040)")
    args = ap.parse_args()
    if args.db and args.conversation_id:
        ap.error("Choose --db or conversation_id, not both")

    try:
        report = inspect_session(args.conversation_id, args.expected_limit, args.db)
    except (Exception, SystemExit) as exc:
        print(json.dumps({"state": "UNKNOWN", "error": str(exc)}, ensure_ascii=False))
        raise SystemExit(2)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not report["latest_limit_ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
