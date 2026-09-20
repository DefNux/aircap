#!/usr/bin/env python3
"""AIRCAP query runner: loads views, then runs a SQL file or an inline statement.

  q.py --sql "SELECT * FROM bedrock_invocations LIMIT 5"
  q.py --file detections/sql/D001-oversized-prompt.sql
  q.py --list
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import duckdb

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("aircap.query")

REPO = Path(__file__).resolve().parent.parent
VIEWS = REPO / "query" / "views.sql"


class QueryError(RuntimeError):
    """Raised when views cannot be built or a query fails."""


def connect(data_dir: Path) -> duckdb.DuckDBPyConnection:
    if not data_dir.is_dir():
        raise QueryError(f"data dir not found: {data_dir} - run the lab first")
    con = duckdb.connect(":memory:")
    con.execute(f"SET VARIABLE data_dir = '{data_dir.as_posix()}'")
    streams = {
        "bedrock-logs": "bedrock_invocations",
        "cloudtrail": "cloudtrail_bedrock",
        "agent-traces": "agent_traces",
    }
    missing = [s for s in streams if not any((data_dir / s).rglob("*.jsonl"))]
    if missing:
        raise QueryError(
            "no telemetry yet for stream(s): "
            + ", ".join(missing)
            + " - generate some with 'make smoke'"
        )
    try:
        con.execute(VIEWS.read_text(encoding="utf-8"))
    except (duckdb.Error, OSError) as exc:
        raise QueryError(f"failed building views: {exc}") from exc
    return con


def main() -> int:
    ap = argparse.ArgumentParser(description="AIRCAP DuckDB query runner")
    ap.add_argument("--data-dir", default=str(REPO / "data"))
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sql", help="inline SQL to execute")
    g.add_argument("--file", help="path to a .sql file")
    g.add_argument("--list", action="store_true", help="list available views")
    args = ap.parse_args()

    try:
        con = connect(Path(args.data_dir).resolve())
        if args.list:
            stmt = "SELECT view_name, column_count FROM duckdb_views() WHERE NOT internal ORDER BY view_name"
        elif args.file:
            stmt = Path(args.file).read_text(encoding="utf-8")
        else:
            stmt = args.sql
        rows = con.sql(stmt)
        rows.show(max_rows=40, max_width=200)
    except (QueryError, duckdb.Error, OSError) as exc:
        logger.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
