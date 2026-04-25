# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF073 (Ruff-specific rules): f string percent format
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf073

import rego.v1

metadata := {
	"id": "RUFF-RUF073",
	"name": "f string percent format",
	"description": "`%` operator used on an f-string",
	"help_uri": "https://docs.astral.sh/ruff/rules/f-string-percent-format/",
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
	"ruff_code": "RUF073",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "f-string-percent-format",
	"ruff_since": "0.15.8",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
