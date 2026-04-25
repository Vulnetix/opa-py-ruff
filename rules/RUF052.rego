# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF052 (Ruff-specific rules): used dummy variable
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf052

import rego.v1

metadata := {
	"id": "RUFF-RUF052",
	"name": "used dummy variable",
	"description": "Local dummy variable `{}` is accessed",
	"help_uri": "https://docs.astral.sh/ruff/rules/used-dummy-variable/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF052",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "used-dummy-variable",
	"ruff_since": "0.8.2",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
