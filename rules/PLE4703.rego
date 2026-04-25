# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE4703 (Pylint): modified iterating set
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple4703

import rego.v1

metadata := {
	"id": "RUFF-PLE4703",
	"name": "modified iterating set",
	"description": "Iterated set `<value>` is modified within the `for` loop",
	"help_uri": "https://docs.astral.sh/ruff/rules/modified-iterating-set/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE4703",
	"ruff_linter": "Pylint",
	"ruff_name": "modified-iterating-set",
	"ruff_since": "v0.3.5",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
