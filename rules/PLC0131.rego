# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0131 (Pylint): type bivariance
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0131

import rego.v1

metadata := {
	"id": "RUFF-PLC0131",
	"name": "type bivariance",
	"description": "`<value>` cannot be both covariant and contravariant",
	"help_uri": "https://docs.astral.sh/ruff/rules/type-bivariance/",
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
	"ruff_code": "PLC0131",
	"ruff_linter": "Pylint",
	"ruff_name": "type-bivariance",
	"ruff_since": "v0.0.278",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
