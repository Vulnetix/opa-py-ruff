# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF051 (Ruff-specific rules): if key in dict del
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf051

import rego.v1

metadata := {
	"id": "RUFF-RUF051",
	"name": "if key in dict del",
	"description": "Use `pop` instead of `key in dict` followed by `del dict[key]`",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-key-in-dict-del/",
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
	"ruff_code": "RUF051",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "if-key-in-dict-del",
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
