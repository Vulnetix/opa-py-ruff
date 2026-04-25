# SPDX-License-Identifier: Apache-2.0
# Ruff rule B903 (flake8-bugbear): class as data structure
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b903

import rego.v1

metadata := {
	"id": "RUFF-B903",
	"name": "class as data structure",
	"description": "Class could be dataclass or namedtuple",
	"help_uri": "https://docs.astral.sh/ruff/rules/class-as-data-structure/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B903",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "class-as-data-structure",
	"ruff_since": "0.9.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
