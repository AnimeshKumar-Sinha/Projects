"""Self-Harness main driver — Algorithm 1 from Zhang et al. 2026."""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime
from pathlib import Path

import yaml

from evaluate import evaluate
from merge import merge
from mine import mine, bundle
from propose import propose
from validate import validate

BASE = Path(__file__).parent


# ── Initial harness h0 ──────────────────────────────────────────────────────

def initial_harness() -> dict:
    return {
        "role": "You are a careful Python programmer.",
        "strategy": "",
        "output_format": "Return ONLY a fenced ```python code block containing your solution function.",
        "checklist": "",
    }


# ── Task loading & split ─────────────────────────────────────────────────────

def load_tasks(tasks_dir: Path) -> list[Path]:
    return sorted(tasks_dir.iterdir())


def split_tasks(tasks: list[Path], ratio: float, seed: int) -> tuple[list[Path], list[Path]]:
    rng = random.Random(seed)
    shuffled = tasks[:]
    rng.shuffle(shuffled)
    cut = round(len(shuffled) * ratio)
    return shuffled[:cut], shuffled[cut:]


# ── Logging helpers ──────────────────────────────────────────────────────────

def _pct(v: float) -> str:
    return f"{v:.0%}"


def _log_round(run_dir: Path, t: int, data: dict) -> None:
    path = run_dir / f"round_{t}.json"
    path.write_text(json.dumps(data, indent=2))


def _snapshot_harness(run_dir: Path, t: int, harness: dict) -> None:
    path = run_dir / f"harness_{t}.json"
    path.write_text(json.dumps(harness, indent=2))


def _write_summary(run_dir: Path, history: list[dict], final_harness: dict) -> None:
    lines = ["# Self-Harness Run Summary\n"]
    lines.append("## Pass Rates per Round\n")
    lines.append("| Round | held-in | held-out | Notes |")
    lines.append("|-------|---------|----------|-------|")
    for h in history:
        lines.append(
            f"| {h['round']:>5} | {_pct(h['in']):>7} | {_pct(h['out']):>8} | {h['note']} |"
        )

    lines.append("\n## Accepted Edits\n")
    for h in history[1:]:
        r = h["round"]
        if h.get("accepted_edits"):
            for e in h["accepted_edits"]:
                lines.append(
                    f"**Round {r}** — `{e['op']}` on `{e['block']}`: {e['rationale']}\n"
                    f"> _{e['text']}_\n"
                    f"> Δ_in={_pct(e['d_in'])}  Δ_out={_pct(e['d_out'])}\n"
                )
        else:
            lines.append(f"**Round {r}** — no edits accepted\n")

    lines.append("\n## Final Harness\n")
    lines.append("```json")
    lines.append(json.dumps(final_harness, indent=2))
    lines.append("```")

    (run_dir / "summary.md").write_text("\n".join(lines) + "\n")


# ── Main loop ────────────────────────────────────────────────────────────────

def run(cfg: dict) -> None:
    model = cfg["model"]
    K = cfg["K"]
    T = cfg["T"]
    split_ratio = cfg["split_ratio"]
    seed = cfg["seed"]
    max_tokens = cfg["max_tokens"]
    timeout = cfg["timeout"]

    tasks_dir = BASE / "tasks"
    run_dir = BASE / "runs" / datetime.now().strftime("%Y%m%dT%H%M%S")
    run_dir.mkdir(parents=True)

    print(f"\n{'='*65}")
    print("  SELF-HARNESS  —  Proof of Concept")
    print(f"{'='*65}")
    print(f"  model={model}  T={T}  K={K}  seed={seed}")
    print(f"  run dir: {run_dir}\n")

    tasks = load_tasks(tasks_dir)
    held_in, held_out = split_tasks(tasks, split_ratio, seed)
    print(f"  Tasks: {len(tasks)} total | {len(held_in)} held-in | {len(held_out)} held-out\n")

    harness = initial_harness()
    _snapshot_harness(run_dir, 0, harness)

    # ── Baseline ─────────────────────────────────────────────────────────────
    print("[ Baseline ]")
    b_in, b_in_recs = evaluate(harness, held_in, model=model, max_tokens=max_tokens, timeout=timeout)
    b_out, _ = evaluate(harness, held_out, model=model, max_tokens=max_tokens, timeout=timeout)
    print(f"  held-in : {_pct(b_in)}  held-out: {_pct(b_out)}")

    history = [{"round": 0, "in": b_in, "out": b_out, "note": "initial harness"}]
    _log_round(run_dir, 0, {"held_in": b_in, "held_out": b_out, "harness": harness})

    cur_in, cur_out = b_in, b_out

    for t in range(T):
        print(f"\n{'─'*65}")
        print(f"  ROUND {t+1} / {T}")
        print(f"{'─'*65}")

        # Stage 1: Weakness Mining
        print("\n[Stage 1 · Weakness Mining]")
        rate_in, records_in = evaluate(harness, held_in, model=model, max_tokens=max_tokens, timeout=timeout)
        failed = [r for r in records_in if not r.passed]
        if not failed:
            print("  All held-in tasks passed — stopping early.")
            break

        patterns = mine(failed, model=model)
        b = bundle(patterns)
        for p in patterns:
            print(f"  ✗ \"{p.name}\" × {p.count}: {p.task_ids}")

        # Stage 2: Harness Proposal
        print(f"\n[Stage 2 · Harness Proposal  (K={K})]")
        edits = propose(harness, b, model=model, K=K)
        print(f"  Generated {len(edits)} proposals")
        if not edits:
            print("  No proposals generated — stopping.")
            break

        # Stage 3: Validation
        print(f"\n[Stage 3 · Proposal Validation]")
        rate_out, _ = evaluate(harness, held_out, model=model, max_tokens=max_tokens, timeout=timeout)
        results = validate(harness, edits, held_in, held_out, rate_in, rate_out,
                           model=model, max_tokens=max_tokens, timeout=timeout)

        accepted = [r for r in results if r["accepted"]]
        rejected = [r for r in results if not r["accepted"]]

        for r in results:
            mark = "✓ ACCEPTED" if r["accepted"] else "✗ REJECTED"
            edit = r["edit"]
            print(f"  {mark}  op={edit['op']} block={edit['block']} "
                  f"Δ_in={_pct(r['d_in'])} Δ_out={_pct(r['d_out'])}")
            print(f"    rationale: {edit.get('rationale', '')[:80]}")

        # Merge
        harness = merge(harness, accepted)
        _snapshot_harness(run_dir, t + 1, harness)

        # Round summary
        new_in, _ = evaluate(harness, held_in, model=model, max_tokens=max_tokens, timeout=timeout)
        new_out, _ = evaluate(harness, held_out, model=model, max_tokens=max_tokens, timeout=timeout)
        print(f"\n  Round {t+1} result:")
        print(f"    held-in : {_pct(new_in)}  (was {_pct(rate_in)})")
        print(f"    held-out: {_pct(new_out)}  (was {_pct(rate_out)})")

        accepted_edits_log = [
            {
                "op": r["edit"]["op"],
                "block": r["edit"]["block"],
                "text": r["edit"]["text"],
                "rationale": r["edit"].get("rationale", ""),
                "d_in": r["d_in"],
                "d_out": r["d_out"],
            }
            for r in accepted
        ]
        rejected_edits_log = [
            {
                "op": r["edit"]["op"],
                "block": r["edit"]["block"],
                "rationale": r["edit"].get("rationale", ""),
                "d_in": r["d_in"],
                "d_out": r["d_out"],
            }
            for r in rejected
        ]

        round_data = {
            "round": t + 1,
            "held_in_before": rate_in,
            "held_out_before": rate_out,
            "held_in_after": new_in,
            "held_out_after": new_out,
            "evidence_bundle": b,
            "accepted_edits": accepted_edits_log,
            "rejected_edits": rejected_edits_log,
            "harness": harness,
        }
        _log_round(run_dir, t + 1, round_data)

        note = f"{len(accepted)} edit(s) accepted" if accepted else "no edits accepted"
        history.append({
            "round": t + 1,
            "in": new_in,
            "out": new_out,
            "note": note,
            "accepted_edits": accepted_edits_log,
        })
        cur_in, cur_out = new_in, new_out

    # Final report
    print(f"\n{'='*65}")
    print("  FINAL RESULTS")
    print(f"{'='*65}")
    print(f"{'Round':>6}  {'held-in':>8}  {'held-out':>9}")
    for h in history:
        print(f"  {h['round']:>4}   {_pct(h['in']):>7}   {_pct(h['out']):>8}")

    _write_summary(run_dir, history, harness)
    print(f"\n  Logs written to: {run_dir}")
    print(f"  summary.md ready for review.")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Self-Harness PoC")
    parser.add_argument("--config", default=str(BASE / "config.yaml"))
    parser.add_argument("--model", default=None)
    parser.add_argument("--T", type=int, default=None, help="Number of rounds")
    parser.add_argument("--K", type=int, default=None, help="Proposals per round")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    if args.model:
        cfg["model"] = args.model
    if args.T is not None:
        cfg["T"] = args.T
    if args.K is not None:
        cfg["K"] = args.K
    if args.seed is not None:
        cfg["seed"] = args.seed

    run(cfg)


if __name__ == "__main__":
    main()
