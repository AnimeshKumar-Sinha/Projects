"""Weakness Mining — cluster failed traces into named failure patterns."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from evaluate import TaskRecord
from model import call_model


@dataclass
class FailurePattern:
    name: str           # short label, e.g. "off-by-one on ranges"
    count: int
    task_ids: list[str]
    description: str
    example_error: str | None


def mine(
    failed_records: list[TaskRecord],
    model: str = "claude-haiku-4-5-20251001",
    max_patterns: int = 5,
) -> list[FailurePattern]:
    """
    Ask the model to cluster failed traces into named failure patterns.
    Returns up to `max_patterns` patterns sorted by frequency.
    """
    if not failed_records:
        return []

    evidence = "\n\n".join(
        f"[{r.task_id}]\n"
        f"error: {r.error or 'none'}\n"
        f"code snippet:\n{(r.extracted_code or r.model_output)[:300]}"
        for r in failed_records
    )

    prompt = f"""You are reviewing failures from a coding agent. Below are {len(failed_records)} failed tasks.

{evidence}

Cluster these failures into at most {max_patterns} distinct, named failure patterns.
Focus on ROOT CAUSE patterns (e.g. "missing edge case for empty input", "wrong return type", "off-by-one error").

Respond with ONLY a JSON array. Each element must have:
  "name": short label (≤8 words)
  "task_ids": list of task_ids that fit this pattern
  "description": one sentence describing the root cause
  "example_error": the most illustrative error string from the tasks (or null)

Return only the JSON array, no prose."""

    try:
        raw = call_model("You are a concise failure analyst.", prompt, model=model, max_tokens=1024, temperature=0.3)
        m = re.search(r"\[.*\]", raw, re.DOTALL)
        if not m:
            return _fallback_cluster(failed_records)
        items = json.loads(m.group())
        patterns = []
        for item in items[:max_patterns]:
            if not isinstance(item, dict):
                continue
            patterns.append(FailurePattern(
                name=item.get("name", "unknown"),
                count=len(item.get("task_ids", [])),
                task_ids=item.get("task_ids", []),
                description=item.get("description", ""),
                example_error=item.get("example_error"),
            ))
        return sorted(patterns, key=lambda p: -p.count)
    except Exception:
        return _fallback_cluster(failed_records)


def _fallback_cluster(failed_records: list[TaskRecord]) -> list[FailurePattern]:
    """Simple deterministic fallback: one bucket per error type."""
    from collections import defaultdict
    buckets: dict[str, list[TaskRecord]] = defaultdict(list)
    for r in failed_records:
        key = (r.error or "unknown")[:40]
        buckets[key].append(r)
    patterns = []
    for key, recs in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        patterns.append(FailurePattern(
            name=key,
            count=len(recs),
            task_ids=[r.task_id for r in recs],
            description=key,
            example_error=recs[0].error,
        ))
    return patterns


def bundle(patterns: list[FailurePattern]) -> dict:
    """Serialise patterns into the evidence bundle B_t."""
    return {
        "total_failures": sum(p.count for p in patterns),
        "patterns": [
            {
                "name": p.name,
                "count": p.count,
                "task_ids": p.task_ids,
                "description": p.description,
                "example_error": p.example_error,
            }
            for p in patterns
        ],
    }
