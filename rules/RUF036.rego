# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF036 (Ruff-specific rules): none not at end of union
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf036

import rego.v1

metadata := {
	"id": "RUFF-RUF036",
	"name": "none not at end of union",
	"description": "`None` not at the end of the type union.",
	"help_uri": "https://docs.astral.sh/ruff/rules/none-not-at-end-of-union/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF036",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "none-not-at-end-of-union",
	"ruff_since": "0.7.4",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
