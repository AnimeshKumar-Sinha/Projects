# Self-Harness Demo

This repository contains a proof-of-concept implementation of a self-improving harness for a fixed foundation model. The harness is the instruction / prompt scaffolding around the model, and the loop iteratively improves that harness by mining failures, proposing targeted edits, validating them, and merging accepted changes.

## Projects

- `self_harness/`
  - Main experimental harness implementation.
  - Coordinates the Self-Harness loop across held-in and held-out tasks.
- `self_harness_poc/`
  - Smaller proof-of-concept harness example.
  - Includes a simplified standalone harness script and requirements.

## How it works

The main loop from `self_harness/loop.py` does the following:

1. Load tasks from `self_harness/tasks/`.
2. Split tasks into held-in and held-out sets.
3. Evaluate the current harness with the fixed model.
4. Mine failure patterns from tasks that failed.
5. Ask the model to propose minimal harness edits.
6. Validate each proposed edit on held-in and held-out tasks.
7. Merge accepted edits into the harness.
8. Repeat for `T` rounds or until no more improvements.

## Key files

- `self_harness/loop.py` — main driver and round orchestration.
- `self_harness/evaluate.py` — runs tasks, calls the model, extracts code, and sandboxes tests.
- `self_harness/model.py` — wraps Anthropic API calls and handles retry logic.
- `self_harness/mine.py` — clusters failed runs into failure patterns.
- `self_harness/propose.py` — generates candidate harness edits.
- `self_harness/validate.py` — evaluates candidate edits for improvement and regression.
- `self_harness/merge.py` — applies accepted edits to update the harness.
- `self_harness/config.yaml` — experiment settings.
- `self_harness/tasks/` — task definitions with `prompt.md` and `tests.py`.

## Requirements

- Python 3.11+ (or whichever Python version matches your environment).
- `anthropic` Python package.
- `ANTHROPIC_API_KEY` environment variable with a valid Anthropic key.

### Example setup

```bash
cd /Users/animeshsinha/Documents/Claude/Projects/Animesh-llm-proj/self_harness
python -m pip install anthropic pyyaml
export ANTHROPIC_API_KEY="sk-..."
```

## Run the harness

From `self_harness/`:

```bash
python loop.py
```

This creates a new run directory under `self_harness/runs/` with per-round JSON records and a `summary.md` file.

## Notes

- The model is fixed; the system prompt / harness changes instead.
- `self_harness_evaluate.py` and the task sandbox ensure proposed solutions are tested automatically.
- The loop only accepts edits that improve held-in or held-out performance without regressing the other.

## License

Add your license information here if needed.
