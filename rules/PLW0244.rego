# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0244 (Pylint): redefined slots in subclass
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0244

import rego.v1

metadata := {
	"id": "RUFF-PLW0244",
	"name": "redefined slots in subclass",
	"description": "Slot `<value>` redefined from base class `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/redefined-slots-in-subclass/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0244",
	"ruff_linter": "Pylint",
	"ruff_name": "redefined-slots-in-subclass",
	"ruff_since": "0.9.3",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
