# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF067 (Ruff-specific rules): non empty init module
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf067

import rego.v1

metadata := {
	"id": "RUFF-RUF067",
	"name": "non empty init module",
	"description": "`__init__` module should not contain any code",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-empty-init-module/",
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
	"ruff_code": "RUF067",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "non-empty-init-module",
	"ruff_since": "0.14.11",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
