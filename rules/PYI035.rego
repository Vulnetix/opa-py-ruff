# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI035 (flake8-pyi): unassigned special variable in stub
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi035

import rego.v1

metadata := {
	"id": "RUFF-PYI035",
	"name": "unassigned special variable in stub",
	"description": "`<value>` in a stub file must have a value, as it has the same semantics as `<value>` at runtime",
	"help_uri": "https://docs.astral.sh/ruff/rules/unassigned-special-variable-in-stub/",
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
	"ruff_code": "PYI035",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "unassigned-special-variable-in-stub",
	"ruff_since": "v0.0.271",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
