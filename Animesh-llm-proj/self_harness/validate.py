"""Proposal Validation — strict gate: Δ_in ≥ 0, Δ_out ≥ 0, max(Δ_in, Δ_out) > 0."""

from __future__ import annotations

from pathlib import Path

from evaluate import evaluate
from propose import apply_edit


def validate(
    harness: dict,
    edits: list[dict],
    held_in: list[Path],
    held_out: list[Path],
    baseline_in: float,
    baseline_out: float,
    model: str = "claude-haiku-4-5-20251001",
    max_tokens: int = 1024,
    timeout: int = 10,
) -> list[dict]:
    """
    Evaluate each candidate edit. Return list of accepted result dicts, sorted
    by combined score descending.

    Each result dict:
      edit, harness_candidate, d_in, d_out, new_in, new_out, accepted
    """
    results = []
    for edit in edits:
        h_candidate = apply_edit(harness, edit)
        new_in, _ = evaluate(h_candidate, held_in, model=model, max_tokens=max_tokens, timeout=timeout)
        new_out, _ = evaluate(h_candidate, held_out, model=model, max_tokens=max_tokens, timeout=timeout)
        d_in = new_in - baseline_in
        d_out = new_out - baseline_out
        accepted = (d_in >= 0) and (d_out >= 0) and (max(d_in, d_out) > 0)
        results.append({
            "edit": edit,
            "harness_candidate": h_candidate,
            "d_in": d_in,
            "d_out": d_out,
            "new_in": new_in,
            "new_out": new_out,
            "accepted": accepted,
        })
    return results
