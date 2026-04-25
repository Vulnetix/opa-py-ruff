# SPDX-License-Identifier: Apache-2.0
# Ruff rule TID254 (flake8-tidy-imports): lazy import mismatch
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tid254

import rego.v1

metadata := {
	"id": "RUFF-TID254",
	"name": "lazy import mismatch",
	"description": "`<value>` should be imported lazily",
	"help_uri": "https://docs.astral.sh/ruff/rules/lazy-import-mismatch/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-tidy-imports", "tid"],
	"ruff_code": "TID254",
	"ruff_linter": "flake8-tidy-imports",
	"ruff_name": "lazy-import-mismatch",
	"ruff_since": "0.15.6",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
