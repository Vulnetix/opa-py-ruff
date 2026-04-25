# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI030 (flake8-pyi): unnecessary literal union
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi030

import rego.v1

metadata := {
	"id": "RUFF-PYI030",
	"name": "unnecessary literal union",
	"description": "Multiple literal members in a union. Use a single literal, e.g. `Literal[{}]`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-literal-union/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI030",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "unnecessary-literal-union",
	"ruff_since": "v0.0.278",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
