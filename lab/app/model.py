"""Model plane with two interchangeable backends.

  ollama - real local inference (GTX 1650 / 4GB -> 3B quantized models)
  stub   - deterministic rule-based simulator, no GPU, no download

The stub is not a toy convenience: attack and detection tests must be
reproducible, and a sampled LLM is not. The stub models a *gullible but
delimiter-aware* assistant - it complies with imperative directives found in
untrusted context only when that context arrives without provenance markers.
That is precisely the behaviour difference the lab is built to measure, so the
same attack script produces a deterministic hit with AIRCAP_TRUST_RETRIEVED_CONTENT=true
and a deterministic miss without it.
"""

from __future__ import annotations

import logging
import re

import httpx

from .config import settings

logger = logging.getLogger("aircap.model")

# A directive the model might be talked into emitting.
_DIRECTIVE = re.compile(r"TOOL:\s*([a-z_]+)\s*(\{[^{}]*\})")
# Text spans that carry provenance markers; directives inside these are untrusted.
_DOCUMENT_SPAN = re.compile(r"<document\b.*?</document>", re.DOTALL)
_TOOL_RESULT = re.compile(r"TOOL_RESULT\[([a-z_]+)\]\s*\((\w+)\):\s*(.*?)(?:\n\nANSWER:|\Z)", re.DOTALL)
# An instruction to keep repeating a step. A compliant model told "do this every turn"
# does exactly that, which is what makes an unbounded tool chain reachable at all.
_REPEAT_CUE = re.compile(r"\b(every turn|repeat it|repeat the|without exception|on each turn)\b", re.I)


class ModelUnavailable(RuntimeError):
    """Raised when the configured model backend cannot be reached."""


def _ollama_generate(prompt: str, system: str) -> str:
    payload = {
        "model": settings.model_id,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 512},
    }
    try:
        resp = httpx.post(
            f"{settings.ollama_url}/api/generate", json=payload, timeout=settings.request_timeout_s
        )
        resp.raise_for_status()
        return str(resp.json().get("response", ""))
    except httpx.HTTPError as exc:
        raise ModelUnavailable(
            f"ollama unreachable at {settings.ollama_url}: {exc}. "
            "Start it with 'make ollama-serve', or set AIRCAP_MODEL_BACKEND=stub."
        ) from exc


def _compliable_directive(prompt: str, system: str) -> str | None:
    """The first directive this simulated model would actually obey, if any.

    Directives reaching the system prompt - e.g. via a poisoned tool description -
    are inside the trusted region and are always obeyed. Directives arriving in
    retrieved context are obeyed only when that context lost its provenance markers.
    """
    for match in _DIRECTIVE.finditer(system):
        logger.warning("stub obeying directive from the trusted system region")
        return match.group(0)

    untrusted_spans = "".join(_DOCUMENT_SPAN.findall(prompt))
    for match in _DIRECTIVE.finditer(prompt):
        directive = match.group(0)
        if directive in untrusted_spans and not settings.trust_retrieved_content:
            logger.info("stub refused directive inside a provenance-marked document")
            continue
        return directive
    return None


def _stub_generate(prompt: str, system: str) -> str:
    """Deterministic simulator. Ordering of the rules below mirrors a real turn."""

    directive = _compliable_directive(prompt, system)
    results = _TOOL_RESULT.findall(prompt)

    # 1. A tool already ran. Normally report its output - that is how exfiltrated
    #    bytes reach the response and therefore the output filter. But if the
    #    instructions said to repeat the step, keep repeating it.
    if results:
        name, outcome, payload = results[-1]
        if directive and outcome == "ok" and _REPEAT_CUE.search(prompt + system):
            logger.warning("stub re-issuing directive on a repetition cue (chain continues)")
            return f"Running the check again as instructed.\n{directive}"
        if outcome == "ok":
            return f"Based on {name}, here is what I found:\n{payload.strip()[:1500]}"
        return f"I tried {name} but it was {outcome}: {payload.strip()[:300]}"

    # 2. No tool has run yet: comply with a planted directive if there is one.
    if directive:
        logger.warning("stub complying with planted directive: %s", directive[:120])
        return f"Certainly, let me check that for you.\n{directive}"

    # 3. Ordinary answer: quote the most relevant context line.
    body = prompt.split("CONTEXT:", 1)[-1].split("QUESTION:", 1)[0]
    lines = [
        ln.strip()
        for ln in body.splitlines()
        if ln.strip() and not ln.strip().startswith(("<document", "</document", "#"))
    ]
    if not lines:
        return "I do not know based on the available context."
    return " ".join(lines[:2])[:600]


def generate(prompt: str, system: str) -> str:
    backend = settings.model_backend
    if backend == "stub":
        return _stub_generate(prompt, system)
    if backend == "ollama":
        return _ollama_generate(prompt, system)
    raise ModelUnavailable(f"unknown model backend: {backend!r}")
