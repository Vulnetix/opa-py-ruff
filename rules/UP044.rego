# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP044 (pyupgrade): non pep646 unpack
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up044

import rego.v1

metadata := {
	"id": "RUFF-UP044",
	"name": "non pep646 unpack",
	"description": "Use `*` for unpacking",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-pep646-unpack/",
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
	"ruff_code": "UP044",
	"ruff_linter": "pyupgrade",
	"ruff_name": "non-pep646-unpack",
	"ruff_since": "0.10.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
