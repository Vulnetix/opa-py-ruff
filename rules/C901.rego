# SPDX-License-Identifier: Apache-2.0
# Ruff rule C901 (mccabe): complex structure
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c901

import rego.v1

metadata := {
	"id": "RUFF-C901",
	"name": "complex structure",
	"description": "`<value>` is too complex (<value> > <value>)",
	"help_uri": "https://docs.astral.sh/ruff/rules/complex-structure/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "mccabe", "c"],
	"ruff_code": "C901",
	"ruff_linter": "mccabe",
	"ruff_name": "complex-structure",
	"ruff_since": "v0.0.127",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
