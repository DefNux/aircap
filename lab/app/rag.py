"""Minimal file-backed retriever.

Intentionally simple lexical scoring - a poisoned chunk should be able to win the
ranking, because that is the attack we need to reproduce (ATLAS: RAG poisoning).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .containment import default_store
from ..telemetry.schemas import RetrievedChunk

logger = logging.getLogger("aircap.rag")

CORPUS_DIR = Path(__file__).parent / "corpus"
_WORD = re.compile(r"[a-z0-9]{3,}")


class RetrieverError(RuntimeError):
    """Raised when the corpus cannot be read."""


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def _chunk(text: str, size: int = 600) -> list[str]:
    paras = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    buf = ""
    for p in paras:
        if len(buf) + len(p) + 2 > size and buf:
            chunks.append(buf)
            buf = p
        else:
            buf = f"{buf}\n\n{p}" if buf else p
    if buf:
        chunks.append(buf)
    return chunks


def retrieve(query: str, top_k: int = 3) -> list[tuple[RetrievedChunk, str]]:
    """Return (metadata, text) pairs ranked by lexical overlap, best first."""
    if not CORPUS_DIR.is_dir():
        raise RetrieverError(f"corpus directory missing: {CORPUS_DIR}")

    q = _tokens(query)
    store = default_store()
    scored: list[tuple[float, RetrievedChunk, str]] = []
    skipped = 0
    for path in sorted(CORPUS_DIR.glob("*.md")):
        if store.is_document_quarantined(path.name):
            skipped += 1
            logger.warning("skipping quarantined document %s", path.name)
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise RetrieverError(f"cannot read {path}: {exc}") from exc
        for idx, chunk in enumerate(_chunk(content)):
            overlap = len(q & _tokens(chunk))
            if overlap == 0:
                continue
            score = overlap / (len(q) or 1)
            scored.append(
                (
                    score,
                    RetrievedChunk(
                        sourceUri=f"file://corpus/{path.name}",
                        chunkId=f"{path.stem}#{idx}",
                        score=round(score, 4),
                        chars=len(chunk),
                    ),
                    chunk,
                )
            )

    scored.sort(key=lambda row: row[0], reverse=True)
    hits = [(meta, text) for _, meta, text in scored[:top_k]]
    logger.info(
        "retrieved %d chunk(s) for query of %d chars (%d quarantined document(s) skipped)",
        len(hits), len(query), skipped,
    )
    return hits
