# SPDX-License-Identifier: Apache-2.0
# Ruff rule E742 (pycodestyle): ambiguous class name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e742

import rego.v1

metadata := {
	"id": "RUFF-E742",
	"name": "ambiguous class name",
	"description": "Ambiguous class name: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/ambiguous-class-name/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E742",
	"ruff_linter": "pycodestyle",
	"ruff_name": "ambiguous-class-name",
	"ruff_since": "v0.0.35",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
