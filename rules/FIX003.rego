# SPDX-License-Identifier: Apache-2.0
# Ruff rule FIX003 (flake8-fixme): line contains xxx
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_fix003

import rego.v1

metadata := {
	"id": "RUFF-FIX003",
	"name": "line contains xxx",
	"description": "Line contains XXX, consider resolving the issue",
	"help_uri": "https://docs.astral.sh/ruff/rules/line-contains-xxx/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-fixme", "fix"],
	"ruff_code": "FIX003",
	"ruff_linter": "flake8-fixme",
	"ruff_name": "line-contains-xxx",
	"ruff_since": "v0.0.272",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
