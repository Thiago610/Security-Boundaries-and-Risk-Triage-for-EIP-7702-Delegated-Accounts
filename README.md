# Guard7702

Offline Python tools for EIP-7702 authorization-state checks, signature recovery and explainable risk scoring. No wallet connection or RPC endpoint required.

## Installation

Requires Python 3.12 or newer. From the repository directory:

```sh
python -m venv .venv
```

Activate on Windows PowerShell with `.venv\Scripts\Activate.ps1`, or on Linux/macOS with `source .venv/bin/activate`. If activation is disabled, invoke the environment's Python directly.

```sh
python -m pip install -e ".[test]"
python run.py test
```

Runtime-only installation: `python -m pip install .`. Alternatively, `python -m pip install -r requirements.txt` installs the editable project with test dependencies.

## Commands

```sh
guard7702 demo
guard7702 inspect examples/observations.jsonl
guard7702 benchmark --seeds 20 --events 2000 --output results
```

You can use `python -m guard7702` or `python run.py` instead of `guard7702`. Use `--help` for command options.

The demo signs an authorization using a public test key, evaluates two modeled chains, and demonstrates same-chain replay rejection. Never fund the test key.

The benchmark checks 48 authorization-state combinations and generates deterministic synthetic comparisons, ablations and threshold sweeps. Default settings generate 80,000 observations. CSV, sample JSONL and metadata files are created only when invoked. Reusing an output directory overwrites the benchmark's named files. Generated outputs are ignored by Git.

## Observation format

The `inspect` command reads UTF-8 JSONL: one object per line, with five required boolean fields:

| Field | Meaning | Weight |
| --- | --- | --- |
| `universal` | Universal chain scope | 2 |
| `unknown_code` | Code without a trusted identity | 2 |
| `code_mismatch` | Code differs from the expected baseline | 4 |
| `burst` | Unusual authorization frequency | 2 |
| `uninitialized` | Initialization context needs review | 2 |

`id` is optional. Default alert threshold: 4; override with `--threshold`.
Invalid JSON, missing/nonboolean features and unreadable files return exit code 2.
Output is streamed: valid earlier lines can be printed before a later input error.
The caller supplies features; automatic on-chain extraction is not included.

The lower-level API supports sparse inputs, treating omitted flags as false:

```python
from guard7702.detector import inspect

result = inspect({"universal": True, "unknown_code": True})
assert result["score"] == 4
assert result["alert"] is True
```

`guard7702.protocol` exposes `Authorization`, `Account`, `World` and `sign`.
See `tests/test_protocol.py` for rollback, clearing, nonce and signature examples.
