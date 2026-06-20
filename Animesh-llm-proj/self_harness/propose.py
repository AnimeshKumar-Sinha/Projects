"""Harness Proposal — ask the model to propose minimal edits to its own harness."""

from __future__ import annotations

import json
import re

from model import call_model

EDITABLE_BLOCKS = {"role", "strategy", "output_format", "checklist"}


def propose(
    harness: dict,
    evidence_bundle: dict,
    model: str = "claude-haiku-4-5-20251001",
    K: int = 4,
) -> list[dict]:
    """
    Generate K diverse, minimal candidate edit ops.
    Each edit: {"op": "append"|"replace", "block": <name>, "text": "...", "rationale": "..."}
    """
    patterns_text = "\n".join(
        f"  [{i+1}] \"{p['name']}\" — {p['count']} tasks: {p['task_ids']}\n"
        f"       {p['description']}\n"
        f"       example error: {p.get('example_error') or 'n/a'}"
        for i, p in enumerate(evidence_bundle.get("patterns", []))
    )

    harness_text = json.dumps(harness, indent=2)

    prompt = f"""You are a harness engineer. The agent below has these failure patterns:

{patterns_text}

Current harness:
{harness_text}

Editable blocks: {sorted(EDITABLE_BLOCKS)}

Propose {K} DISTINCT, MINIMAL harness edits. Rules:
- Each edit targets exactly ONE failure pattern.
- Each edit touches only ONE block.
- Use op "append" to add text to the end of a block, "replace" to overwrite it.
- Keep edits short (1-3 sentences). Do NOT rewrite the whole harness.
- Proposals must be materially different from each other.

Respond with ONLY a JSON array of {K} objects, each with keys:
  "op": "append" or "replace"
  "block": one of {sorted(EDITABLE_BLOCKS)}
  "text": the new/appended text
  "rationale": which failure pattern this targets and why

Return only the JSON array."""

    try:
        raw = call_model(
            "You are a concise harness engineer. Output only valid JSON.",
            prompt,
            model=model,
            max_tokens=1500,
            temperature=0.7,  # warmer for diversity
        )
        m = re.search(r"\[.*\]", raw, re.DOTALL)
        if not m:
            return []
        items = json.loads(m.group())
        valid = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("op") not in ("append", "replace"):
                continue
            if item.get("block") not in EDITABLE_BLOCKS:
                continue
            if not item.get("text"):
                continue
            valid.append(item)
        return valid[:K]
    except Exception as e:
        print(f"  [propose error]: {e}")
        return []


def apply_edit(harness: dict, edit: dict) -> dict:
    """Apply a single edit op to a harness dict, returning a new dict."""
    import copy
    h = copy.deepcopy(harness)
    block = edit["block"]
    text = edit["text"].strip()
    if edit["op"] == "replace":
        h[block] = text
    else:  # append
        existing = h.get(block, "").strip()
        h[block] = f"{existing}\n{text}".strip() if existing else text
    return h
