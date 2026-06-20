"""EVALUATE(M, h, split) — run model under a harness, sandbox-test the output."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from model import call_model


@dataclass
class TaskRecord:
    task_id: str
    passed: bool
    model_output: str
    extracted_code: str | None
    error: str | None      # None when passed
    trace: str | None = None


def _extract_code(response: str) -> str | None:
    """Pull Python from a ```python ... ``` fence, or bare def solution(...)."""
    m = re.search(r"```python\s*(.*?)\s*```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\s*(.*?)\s*```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(r"(def solution\b.*?)(?=\ndef |\Z)", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None


def _run_in_sandbox(code: str, tests_path: Path, timeout: int) -> tuple[bool, str | None]:
    """
    Write code to a temp solution.py, run tests.py in a sandboxed subprocess.
    Returns (passed, error_detail).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        sol_path = Path(tmpdir) / "solution.py"
        sol_path.write_text(code)

        # Copy tests next to solution so `from solution import solution` works
        test_code = tests_path.read_text()
        test_path = Path(tmpdir) / "tests.py"
        test_path.write_text(test_code)

        try:
            result = subprocess.run(
                [sys.executable, str(test_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
            )
            if result.returncode == 0:
                return True, None
            stderr = (result.stderr or result.stdout or "").strip()
            return False, stderr[:500]
        except subprocess.TimeoutExpired:
            return False, f"timeout after {timeout}s"
        except Exception as e:
            return False, f"subprocess_error: {e}"


def _harness_system(harness: dict) -> str:
    order = ["role", "strategy", "output_format", "checklist"]
    parts = [harness[k] for k in order if harness.get(k)]
    return "\n\n".join(parts)


def evaluate(
    harness: dict,
    tasks: list[Path],
    model: str = "claude-haiku-4-5-20251001",
    max_tokens: int = 1024,
    timeout: int = 10,
) -> tuple[float, list[TaskRecord]]:
    """
    Run every task in `tasks` through the model under `harness`.
    Returns (pass_rate, records).
    """
    system = _harness_system(harness)
    records: list[TaskRecord] = []

    for task_dir in tasks:
        task_id = task_dir.name
        prompt_text = (task_dir / "prompt.md").read_text()
        tests_path = task_dir / "tests.py"

        user_prompt = (
            f"{prompt_text}\n\n"
            "Provide your answer as a Python function inside a ```python ... ``` code block."
        )

        try:
            response = call_model(system, user_prompt, model=model, max_tokens=max_tokens)
        except Exception as e:
            records.append(TaskRecord(task_id, False, "", None, f"api_error: {e}"))
            continue

        code = _extract_code(response)
        if code is None:
            records.append(TaskRecord(task_id, False, response, None, "no_code_block"))
            continue

        passed, error = _run_in_sandbox(code, tests_path, timeout)
        records.append(TaskRecord(task_id, passed, response, code, error))

    n = len(records)
    rate = sum(r.passed for r in records) / n if n else 0.0
    return rate, records
