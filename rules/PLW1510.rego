# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW1510 (Pylint): subprocess run without check
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw1510

import rego.v1

metadata := {
	"id": "RUFF-PLW1510",
	"name": "subprocess run without check",
	"description": "`subprocess.run` without explicit `check` argument",
	"help_uri": "https://docs.astral.sh/ruff/rules/subprocess-run-without-check/",
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
	"ruff_code": "PLW1510",
	"ruff_linter": "Pylint",
	"ruff_name": "subprocess-run-without-check",
	"ruff_since": "v0.0.285",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
