# opa-py-ruff

Vulnetix OPA/Rego SAST rules — clean-room implementation of [Ruff](https://github.com/astral-sh/ruff) Python linting rules.

## Overview

This repository contains [Open Policy Agent](https://www.openpolicyagent.org/) Rego rules for the [Vulnetix CLI](https://github.com/Vulnetix/cli) SAST scanner. Each rule is a clean-room implementation of a [Ruff](https://docs.astral.sh/ruff/rules/) rule, preserving the original rule metadata (code, linter, summary, fix availability).

- **956 rules** covering all Ruff rule codes
- **478 rules** with regex/pattern-based detection
- **478 rules** as stubs (require AST analysis beyond Rego's capability)
- Full Ruff metadata retained in each rule's `metadata` block

## Rule Metadata

Every rule includes:

```rego
metadata := {
    "id": "RUFF-S101",
    "ruff_code": "S101",
    "ruff_linter": "flake8-bandit",
    "ruff_name": "assert",
    "ruff_since": "v0.0.x",
    "ruff_fix": "None",
    "help_uri": "https://docs.astral.sh/ruff/rules/assert/",
    ...
}
```

## Usage

```bash
# Scan with ruff rules only (disable built-in Vulnetix rules)
vulnetix scan --rule Vulnetix/opa-py-ruff --disable-default-rules

# Scan with both built-in and ruff rules
vulnetix scan --rule Vulnetix/opa-py-ruff
```

## Rule Coverage

| Prefix | Count | Linter | Detection |
|--------|-------|--------|-----------|
| A | 6 | flake8-builtins | Pattern |
| AIR | 12 | Airflow | Stub |
| ANN | 11 | flake8-annotations | Pattern |
| ARG | 5 | flake8-unused-arguments | Pattern/Stub |
| ASYNC | 15 | flake8-async | Pattern |
| B | 43 | flake8-bugbear | Pattern |
| BLE | 1 | flake8-blind-except | Pattern |
| C | 20 | flake8-comprehensions | Stub |
| COM | 3 | flake8-commas | Pattern |
| D | 47 | pydocstyle | Stub |
| DJ | 7 | flake8-django | Pattern |
| DTZ | 10 | flake8-datetimez | Pattern |
| E | 60 | pycodestyle | Pattern |
| EM | 3 | flake8-errmsg | Pattern |
| ERA | 1 | eradicate | Pattern |
| F | 43 | Pyflakes | Pattern/Stub |
| FURB | 36 | refurb | Pattern |
| G | 8 | flake8-logging-format | Pattern |
| I | 2 | isort | Stub |
| N | 16 | pep8-naming | Pattern |
| PERF | 6 | Perflint | Pattern |
| PGH | 5 | pygrep-hooks | Pattern |
| PIE | 8 | flake8-pie | Pattern |
| PLC | 16 | Pylint | Pattern |
| PLE | 38 | Pylint | Pattern |
| PLR | 33 | Pylint | Pattern |
| PLW | 28 | Pylint | Pattern |
| PT | 31 | flake8-pytest-style | Pattern |
| PTH | 35 | flake8-use-pathlib | Pattern |
| PYI | 55 | flake8-pyi | Pattern/Stub |
| Q | 5 | flake8-quotes | Pattern |
| RET | 8 | flake8-return | Pattern |
| RUF | 73 | Ruff-specific | Pattern/Stub |
| S | 73 | flake8-bandit | Pattern |
| SIM | 30 | flake8-simplify | Pattern |
| T | 3 | flake8-debugger | Pattern |
| TC | 9 | flake8-type-checking | Pattern |
| TID | 4 | flake8-tidy-imports | Pattern |
| TRY | 10 | tryceratops | Pattern |
| UP | 47 | pyupgrade | Pattern |
| W | 7 | pycodestyle | Pattern |
| YTT | 10 | flake8-2020 | Pattern |

## License

Apache-2.0
