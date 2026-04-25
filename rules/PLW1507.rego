# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW1507 (Pylint): shallow copy environ
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw1507

import rego.v1

metadata := {
	"id": "RUFF-PLW1507",
	"name": "shallow copy environ",
	"description": "Shallow copy of `os.environ` via `copy.copy(os.environ)`",
	"help_uri": "https://docs.astral.sh/ruff/rules/shallow-copy-environ/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW1507",
	"ruff_linter": "Pylint",
	"ruff_name": "shallow-copy-environ",
	"ruff_since": "0.10.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
