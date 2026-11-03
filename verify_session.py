#!/usr/bin/env python3
"""
Read-only verifier for Antigravity IDE / Desktop / CLI SQLite conversation databases.
Checks:
- Both ~/.gemini/antigravity/conversations/<cid>.db and ~/.gemini/antigravity-cli/conversations/<cid>.db
- Latest turn (and idx=0) executor_metadata checkpoint max_token_limit (expected 983040)
- Latest turn (and idx=0) gen_metadata ChatStartMetadata.ContextWindowMetadata.max_context_tokens (expected 983040)
- Optional AGENTS.md full injection in user_rules section without budget exclusion notice
"""

import argparse
import json
import sqlite3
from pathlib import Path


def read_varint(b: bytes, p: int):
    v = s = 0
    while True:
        x = b[p]
        p += 1
        v |= (x & 127) << s
        s += 7
        if x < 128:
            return v, p
        if s > 70:
            raise ValueError("Invalid protobuf varint")


def iter_fields(b: bytes):
    p = 0
    while p < len(b):
        t, p = read_varint(b, p)
        w = t & 7
        if w == 0:
            v, p = read_varint(b, p)
        elif w == 2:
            n, p = read_varint(b, p)
            v = b[p : p + n]
            p += n
        elif w in (1, 5):
            n = 8 if w == 1 else 4
            v = b[p : p + n]
            p += n
        else:
            raise ValueError(f"Unsupported wire type: {w}")
        yield t >> 3, w, v


def get_field(b: bytes, k: int):
    return next(v for f, w, v in iter_fields(b) if f == k)


def find_conversation_db(cid: str | None) -> Path:
    dirs = [
        Path.home() / ".gemini" / "antigravity" / "conversations",
        Path.home() / ".gemini" / "antigravity-cli" / "conversations",
    ]
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
    return max(all_dbs, key=lambda p: p.stat().st_mtime)


def parse_gen_row(g: bytes):
    chat = get_field(g, 1)
    window = get_field(get_field(chat, 9), 10)
    gen_limit = get_field(window, 4)
    return chat, gen_limit


def parse_exec_row(e: bytes):
    return get_field(get_field(get_field(e, 10), 2), 5)


def main():
    ap = argparse.ArgumentParser(description="Verify actual request context window and AGENTS.md injection in session DB.")
    ap.add_argument("conversation_id", nargs="?", help="Conversation UUID (omit to inspect the newest .db automatically)")
    ap.add_argument("--agents", type=Path, help="Optional path to project AGENTS.md to verify full byte-for-byte injection")
    ap.add_argument("--expected-limit", type=int, default=983040, help="Expected max_context_tokens (default: 983040)")
    args = ap.parse_args()

    db_path = find_conversation_db(args.conversation_id)
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)

    g_first_idx, g_first = conn.execute("select idx, data from gen_metadata order by idx asc limit 1").fetchone()
    g_last_idx, g_last = conn.execute("select idx, data from gen_metadata order by idx desc limit 1").fetchone()
    _, gen_limit_first = parse_gen_row(g_first)
    chat_last, gen_limit_last = parse_gen_row(g_last)

    e_first_idx, e_first = conn.execute("select idx, data from executor_metadata order by idx asc limit 1").fetchone()
    e_last_idx, e_last = conn.execute("select idx, data from executor_metadata order by idx desc limit 1").fetchone()
    exec_limit_first = parse_exec_row(e_first)
    exec_limit_last = parse_exec_row(e_last)

    sections = []
    original_agents = args.agents.read_bytes() if args.agents else None
    for f, w, v in iter_fields(chat_last):
        if f == 16:
            title = get_field(v, 1).decode("utf-8", errors="replace")
            content = get_field(v, 2)
            if b"AGENTS.md" in content or title == "user_rules":
                entry = {
                    "title": title,
                    "bytes": len(content),
                    "excluded": b"exceeded the rules token budget" in content,
                }
                if original_agents is not None:
                    entry["contains_full_agents"] = original_agents in content
                sections.append(entry)

    report = {
        "db_path": str(db_path),
        "conversation_id": db_path.stem,
        "first_turn": {
            "gen_idx": g_first_idx,
            "gen_max_context_tokens": gen_limit_first,
            "executor_idx": e_first_idx,
            "executor_max_token_limit": exec_limit_first,
        },
        "latest_turn": {
            "gen_idx": g_last_idx,
            "gen_max_context_tokens": gen_limit_last,
            "executor_idx": e_last_idx,
            "executor_max_token_limit": exec_limit_last,
        },
        "expected_limit": args.expected_limit,
        "latest_limit_ok": (gen_limit_last == args.expected_limit and exec_limit_last == args.expected_limit),
        "sections": sections,
    }
    if original_agents is not None:
        report["agents_bytes"] = len(original_agents)
        report["agents_ok"] = any(s.get("contains_full_agents") and not s["excluded"] for s in sections)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not report["latest_limit_ok"] or (original_agents is not None and not report["agents_ok"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
