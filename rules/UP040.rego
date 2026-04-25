# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP040 (pyupgrade): non pep695 type alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up040

import rego.v1

metadata := {
	"id": "RUFF-UP040",
	"name": "non pep695 type alias",
	"description": "Type alias `<value>` uses <value> instead of the `type` keyword",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-pep695-type-alias/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP040",
	"ruff_linter": "pyupgrade",
	"ruff_name": "non-pep695-type-alias",
	"ruff_since": "v0.0.283",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
