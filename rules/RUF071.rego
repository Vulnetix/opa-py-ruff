# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF071 (Ruff-specific rules): os path commonprefix
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf071

import rego.v1

metadata := {
	"id": "RUFF-RUF071",
	"name": "os path commonprefix",
	"description": "`os.path.commonprefix()` compares strings character-by-character",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-path-commonprefix/",
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
	"ruff_code": "RUF071",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "os-path-commonprefix",
	"ruff_since": "0.15.6",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
