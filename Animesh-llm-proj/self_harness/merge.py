"""MERGEACCEPTED — apply all accepted edits to produce h_{t+1}."""

from __future__ import annotations

from propose import apply_edit, EDITABLE_BLOCKS


def merge(harness: dict, accepted_results: list[dict]) -> dict:
    """
    Apply accepted edits to harness. If multiple edits touch the same block,
    sort by combined delta (d_in + d_out) descending and append in that order.
    Returns the updated harness.
    """
    if not accepted_results:
        return harness

    # Sort by combined improvement so best edits are applied first
    sorted_results = sorted(
        accepted_results,
        key=lambda r: r["d_in"] + r["d_out"],
        reverse=True,
    )

    h = harness
    for result in sorted_results:
        h = apply_edit(h, result["edit"])

    return h
