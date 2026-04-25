# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0205 (Pylint): single string slots
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0205

import rego.v1

metadata := {
	"id": "RUFF-PLC0205",
	"name": "single string slots",
	"description": "Class `__slots__` should be a non-string iterable",
	"help_uri": "https://docs.astral.sh/ruff/rules/single-string-slots/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plc"],
	"ruff_code": "PLC0205",
	"ruff_linter": "Pylint",
	"ruff_name": "single-string-slots",
	"ruff_since": "v0.0.276",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
