"""
Self-Harness: Proof of Concept
================================
Based on "Self-Harness: Harnesses That Improve Themselves" (Zhang et al., 2026)

This demo implements the three-stage Self-Harness loop:
  1. Weakness Mining   — identify failure patterns from execution traces
  2. Harness Proposal  — use the same model to propose targeted harness edits
  3. Proposal Validation — accept edits only if they improve without regression

The "agent" is given simple Python coding tasks. Its harness is the system prompt
and instruction config. Self-Harness iteratively improves that config by observing
what the agent gets wrong and asking it to propose better instructions for itself.

Usage:
    export ANTHROPIC_API_KEY=sk-...
    python self_harness.py
"""

import anthropic
import json
import os
import re
import sys
from dataclasses import dataclass, field
from copy import deepcopy


# ══════════════════════════════════════════════════════════════════════════════
# 1. HARNESS  — the non-parametric scaffolding around the fixed model
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Harness:
    """
    The agent harness: system prompt + configurable instruction surfaces.
    Only this object changes across rounds — the model weights never do.
    """
    system_prompt: str
    bootstrap_instruction: str       # what to do first
    execution_instruction: str       # how to work through the task
    verification_instruction: str    # what to check before finishing
    failure_recovery_instruction: str  # what to do when something goes wrong

    def to_system_message(self) -> str:
        """Assemble the full system prompt sent to the model."""
        return (
            f"{self.system_prompt}\n\n"
            f"Before you start: {self.bootstrap_instruction}\n"
            f"While working: {self.execution_instruction}\n"
            f"Before you finish: {self.verification_instruction}\n"
            f"If something fails: {self.failure_recovery_instruction}"
        )

    def as_dict(self) -> dict:
        return {
            "system_prompt": self.system_prompt,
            "bootstrap_instruction": self.bootstrap_instruction,
            "execution_instruction": self.execution_instruction,
            "verification_instruction": self.verification_instruction,
            "failure_recovery_instruction": self.failure_recovery_instruction,
        }


def make_initial_harness() -> Harness:
    """
    Intentionally minimal — mimics the paper's sparse initial harness.
    Self-Harness will iteratively enrich this.
    """
    return Harness(
        system_prompt="You are a coding agent. Solve the given programming task.",
        bootstrap_instruction="Read the task carefully.",
        execution_instruction="Write clean, working Python code.",
        verification_instruction="Check your solution is correct before finishing.",
        failure_recovery_instruction="If your approach fails, try a different one.",
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. BENCHMARK TASKS  — held-in (visible to proposer) + held-out (regression gate)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Task:
    task_id: str
    description: str
    test_cases: list[tuple]   # each entry: (single_arg, expected_return_value)


# The agent must write a function named exactly `solution`.
# Evaluator runs it against test_cases.

HELD_IN: list[Task] = [
    Task("reverse_string",
         "Write a Python function called `solution(s)` that reverses the string s and returns it.",
         [("hello", "olleh"), ("", ""), ("abcd", "dcba")]),

    Task("count_vowels",
         "Write a Python function called `solution(s)` that counts vowels (a e i o u, "
         "case-insensitive) in string s and returns the count.",
         [("hello", 2), ("AEIOU", 5), ("xyz", 0)]),

    Task("sum_evens",
         "Write a Python function called `solution(lst)` that returns the sum of all "
         "even numbers in the list lst.",
         [([1, 2, 3, 4], 6), ([], 0), ([1, 3, 5], 0)]),

    Task("is_palindrome",
         "Write a Python function called `solution(s)` that returns True if s is a "
         "palindrome, False otherwise.",
         [("racecar", True), ("hello", False), ("", True)]),

    Task("max_element",
         "Write a Python function called `solution(lst)` that returns the maximum "
         "element in the non-empty list lst.",
         [([1, 5, 3], 5), ([42], 42), ([-1, -2, -3], -1)]),
]

HELD_OUT: list[Task] = [
    Task("fizzbuzz",
         "Write a Python function called `solution(n)` that returns 'Fizz' if n is "
         "divisible by 3, 'Buzz' if divisible by 5, 'FizzBuzz' if both, otherwise "
         "the string representation of n.",
         [(3, "Fizz"), (5, "Buzz"), (15, "FizzBuzz"), (7, "7")]),

    Task("flatten_list",
         "Write a Python function called `solution(lst)` that flattens a one-level "
         "nested list (list of lists) into a single flat list.",
         [([[1, 2], [3, 4]], [1, 2, 3, 4]), ([[]], []), ([[1], [2], [3]], [1, 2, 3])]),

    Task("word_count",
         "Write a Python function called `solution(s)` that returns the number of "
         "words in string s (words are separated by spaces). An empty string has 0 words.",
         [("hello world", 2), ("", 0), ("one", 1)]),

    Task("unique_sorted",
         "Write a Python function called `solution(lst)` that returns a sorted list "
         "of unique elements from lst.",
         [([1, 2, 2, 3], [1, 2, 3]), ([], []), ([5, 5, 5], [5])]),

    Task("digit_sum",
         "Write a Python function called `solution(n)` that returns the sum of the "
         "decimal digits of the non-negative integer n.",
         [(123, 6), (0, 0), (999, 27)]),
]


# ══════════════════════════════════════════════════════════════════════════════
# 3. EVALUATOR  — run model under harness, extract code, verify correctness
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TraceRecord:
    task_id: str
    passed: bool
    model_response: str
    extracted_code: str | None
    failure_reason: str | None   # None when passed
    error_detail: str | None = None


def extract_code(response: str) -> str | None:
    """Pull Python code out of a markdown code fence."""
    # ```python ... ```
    m = re.search(r"```python\s*(.*?)\s*```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    # ``` ... ```
    m = re.search(r"```\s*(.*?)\s*```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    # bare def solution(...) anywhere in the text
    m = re.search(r"(def solution\(.*?)(?=\ndef |\Z)", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None


def run_against_tests(code: str, test_cases: list[tuple]) -> tuple[bool, str | None]:
    """Execute extracted code and check all test cases. Returns (passed, error_detail)."""
    ns: dict = {}
    try:
        exec(compile(code, "<harness_eval>", "exec"), ns)
    except Exception as e:
        return False, f"exec_error: {e}"

    if "solution" not in ns:
        return False, "wrong_function_name: no function named 'solution' found"

    fn = ns["solution"]
    for arg, expected in test_cases:
        try:
            result = fn(arg)
            if result != expected:
                return False, f"wrong_output: solution({arg!r}) → {result!r}, expected {expected!r}"
        except Exception as e:
            return False, f"runtime_error on input {arg!r}: {e}"

    return True, None


def evaluate(client: anthropic.Anthropic, harness: Harness, tasks: list[Task]) -> list[TraceRecord]:
    """Run every task through the model under the given harness."""
    records: list[TraceRecord] = []
    system = harness.to_system_message()

    for task in tasks:
        user_prompt = (
            f"Task: {task.description}\n\n"
            "Provide your answer as a Python function in a ```python ... ``` code block."
        )

        try:
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user_prompt}],
            )
            response = msg.content[0].text
        except Exception as e:
            records.append(TraceRecord(task.task_id, False, "", None, "api_error", str(e)))
            continue

        code = extract_code(response)
        if code is None:
            records.append(TraceRecord(task.task_id, False, response, None, "no_code_block"))
            continue

        passed, error = run_against_tests(code, task.test_cases)
        if passed:
            records.append(TraceRecord(task.task_id, True, response, code, None))
        else:
            # Map raw error string to a clean failure category
            if error and "exec_error" in error:
                reason = "syntax_or_import_error"
            elif error and "wrong_function_name" in error:
                reason = "wrong_function_name"
            elif error and "wrong_output" in error:
                reason = "wrong_output"
            elif error and "runtime_error" in error:
                reason = "runtime_error"
            else:
                reason = "unknown"
            records.append(TraceRecord(task.task_id, False, response, code, reason, error))

    return records


def pass_rate(records: list[TraceRecord]) -> float:
    return sum(r.passed for r in records) / len(records) if records else 0.0


def fmt(records: list[TraceRecord]) -> str:
    n = len(records)
    p = sum(r.passed for r in records)
    return f"{p}/{n} ({p/n:.0%})"


# ══════════════════════════════════════════════════════════════════════════════
# 4. WEAKNESS MINING  — cluster failures by verifier-grounded signature
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FailurePattern:
    reason: str          # failure category (the cluster key)
    count: int
    task_ids: list[str]
    example_error: str | None
    example_response_snippet: str


def mine_weaknesses(records: list[TraceRecord]) -> list[FailurePattern]:
    """
    Group failed traces by their failure_reason (the verifier-grounded signature).
    Returns patterns sorted by frequency (most common first).
    """
    from collections import defaultdict
    clusters: dict[str, list[TraceRecord]] = defaultdict(list)

    for r in records:
        if not r.passed and r.failure_reason:
            clusters[r.failure_reason].append(r)

    patterns = []
    for reason, recs in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
        patterns.append(FailurePattern(
            reason=reason,
            count=len(recs),
            task_ids=[r.task_id for r in recs],
            example_error=recs[0].error_detail,
            example_response_snippet=recs[0].model_response[:300],
        ))
    return patterns


# ══════════════════════════════════════════════════════════════════════════════
# 5. HARNESS PROPOSAL  — the model proposes edits to its own harness
# ══════════════════════════════════════════════════════════════════════════════

def propose_harness_modifications(
    client: anthropic.Anthropic,
    current_harness: Harness,
    patterns: list[FailurePattern],
    k: int = 3,
) -> list[dict]:
    """
    Invoke the same fixed model in a *proposer role*: given structured failure
    evidence, generate k distinct minimal harness modifications.
    """
    patterns_text = "\n".join(
        f"  [{i+1}] Failure '{p.reason}' — {p.count} times on tasks {p.task_ids}\n"
        f"      Example error : {p.example_error}\n"
        f"      Agent response: {p.example_response_snippet[:200]!r}"
        for i, p in enumerate(patterns)
    )

    prompt = f"""You are a harness engineer reviewing an LLM agent's failures.

Current harness (JSON):
{json.dumps(current_harness.as_dict(), indent=2)}

Failure patterns observed across execution traces:
{patterns_text}

Propose {k} DISTINCT, MINIMAL harness modifications that target specific failure patterns.
Rules:
- Each proposal must address one primary failure mechanism.
- Change only what is needed; keep unrelated instructions intact.
- Proposals must be materially different from each other.

Respond with ONLY a JSON array of {k} objects. Each object must have these keys:
  "system_prompt", "bootstrap_instruction", "execution_instruction",
  "verification_instruction", "failure_recovery_instruction", "rationale"

The "rationale" field should name the failure pattern targeted and why the edit helps."""

    try:
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = msg.content[0].text
        m = re.search(r"\[.*\]", raw, re.DOTALL)
        if m:
            proposals = json.loads(m.group())
            return [p for p in proposals if isinstance(p, dict)][:k]
    except Exception as e:
        print(f"      [proposal error]: {e}")
    return []


def harness_from_proposal(p: dict) -> Harness:
    return Harness(
        system_prompt=p.get("system_prompt", ""),
        bootstrap_instruction=p.get("bootstrap_instruction", ""),
        execution_instruction=p.get("execution_instruction", ""),
        verification_instruction=p.get("verification_instruction", ""),
        failure_recovery_instruction=p.get("failure_recovery_instruction", ""),
    )


# ══════════════════════════════════════════════════════════════════════════════
# 6. PROPOSAL VALIDATION  — accept only non-regressive improvements
# ══════════════════════════════════════════════════════════════════════════════

def validate_proposals(
    client: anthropic.Anthropic,
    current_harness: Harness,
    proposals: list[dict],
    held_in: list[Task],
    held_out: list[Task],
    baseline_in: float,
    baseline_out: float,
) -> Harness:
    """
    Evaluate each candidate harness on both splits.
    Acceptance rule (from the paper):
        Δ_in ≥ 0  AND  Δ_out ≥ 0  AND  max(Δ_in, Δ_out) > 0
    If multiple pass, keep the one with the highest combined pass rate.
    """
    accepted: list[tuple[Harness, float, str]] = []

    for i, prop in enumerate(proposals):
        rationale = prop.get("rationale", "")[:80]
        print(f"    Proposal {i+1}: {rationale}")

        candidate = harness_from_proposal(prop)
        in_rec = evaluate(client, candidate, held_in)
        out_rec = evaluate(client, candidate, held_out)

        new_in = pass_rate(in_rec)
        new_out = pass_rate(out_rec)
        d_in = new_in - baseline_in
        d_out = new_out - baseline_out

        print(f"      held-in : {baseline_in:.0%} → {new_in:.0%}  (Δ={d_in:+.0%})")
        print(f"      held-out: {baseline_out:.0%} → {new_out:.0%}  (Δ={d_out:+.0%})")

        if d_in >= 0 and d_out >= 0 and max(d_in, d_out) > 0:
            print(f"      ✓ ACCEPTED")
            accepted.append((candidate, new_in + new_out, rationale))
        else:
            print(f"      ✗ REJECTED")

    if accepted:
        best_harness, _, best_rationale = max(accepted, key=lambda x: x[1])
        print(f"\n    → Merging best accepted edit: {best_rationale}")
        return best_harness

    print(f"\n    → No proposals accepted — harness unchanged")
    return current_harness


# ══════════════════════════════════════════════════════════════════════════════
# 7. MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════

def run_self_harness(rounds: int = 3, k_proposals: int = 3) -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        sys.exit("Error: ANTHROPIC_API_KEY environment variable not set.")

    client = anthropic.Anthropic(api_key=api_key)
    harness = make_initial_harness()

    print("=" * 65)
    print("  SELF-HARNESS  —  Proof of Concept")
    print("=" * 65)
    print(f"\nInitial system prompt: {harness.system_prompt!r}")
    print(f"Benchmark: {len(HELD_IN)} held-in tasks, {len(HELD_OUT)} held-out tasks")
    print(f"Rounds: {rounds}   Proposals per round: {k_proposals}\n")

    # ── Baseline evaluation ──────────────────────────────────────────────────
    print("[ Baseline Evaluation ]")
    b_in_rec  = evaluate(client, harness, HELD_IN)
    b_out_rec = evaluate(client, harness, HELD_OUT)
    b_in  = pass_rate(b_in_rec)
    b_out = pass_rate(b_out_rec)
    print(f"  held-in : {fmt(b_in_rec)}")
    print(f"  held-out: {fmt(b_out_rec)}")

    history = [{"round": 0, "in": b_in, "out": b_out, "note": "initial harness"}]

    # ── Iterative Self-Harness loop ──────────────────────────────────────────
    for t in range(rounds):
        print(f"\n{'─'*65}")
        print(f"  ROUND {t+1} / {rounds}")
        print(f"{'─'*65}")

        # ── Stage 1: Weakness Mining ─────────────────────────────────────────
        print("\n[Stage 1 · Weakness Mining]")
        in_records = evaluate(client, harness, HELD_IN)
        patterns   = mine_weaknesses(in_records)

        if not patterns:
            print("  All held-in tasks passed — stopping early.")
            break

        for p in patterns:
            print(f"  ✗ '{p.reason}' × {p.count} tasks: {p.task_ids}")

        # ── Stage 2: Harness Proposal ────────────────────────────────────────
        print(f"\n[Stage 2 · Harness Proposal  ({k_proposals} candidates)]")
        proposals = propose_harness_modifications(client, harness, patterns, k=k_proposals)

        if not proposals:
            print("  Model generated no proposals — stopping.")
            break

        print(f"  Generated {len(proposals)} proposals")

        # ── Stage 3: Proposal Validation ─────────────────────────────────────
        print(f"\n[Stage 3 · Proposal Validation]")
        cur_in  = pass_rate(in_records)
        cur_out = pass_rate(evaluate(client, harness, HELD_OUT))

        harness = validate_proposals(
            client, harness, proposals,
            HELD_IN, HELD_OUT,
            cur_in, cur_out,
        )

        # ── Round summary ────────────────────────────────────────────────────
        final_in  = evaluate(client, harness, HELD_IN)
        final_out = evaluate(client, harness, HELD_OUT)
        new_in    = pass_rate(final_in)
        new_out   = pass_rate(final_out)

        print(f"\n  Round {t+1} result:")
        print(f"    held-in : {fmt(final_in)}   (was {cur_in:.0%})")
        print(f"    held-out: {fmt(final_out)}   (was {cur_out:.0%})")

        history.append({"round": t+1, "in": new_in, "out": new_out,
                         "note": harness.bootstrap_instruction[:50]})

    # ── Final report ─────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print("  FINAL RESULTS")
    print(f"{'='*65}")
    print(f"{'Round':>6}  {'held-in':>8}  {'held-out':>9}")
    for h in history:
        print(f"  {h['round']:>4}   {h['in']:>7.0%}   {h['out']:>8.0%}")

    print(f"\nFinal harness configuration:")
    for k, v in harness.as_dict().items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    run_self_harness(rounds=3, k_proposals=3)
