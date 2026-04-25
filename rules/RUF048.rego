# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF048 (Ruff-specific rules): map int version parsing
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf048

import rego.v1

metadata := {
	"id": "RUFF-RUF048",
	"name": "map int version parsing",
	"description": "`__version__` may contain non-integral-like elements",
	"help_uri": "https://docs.astral.sh/ruff/rules/map-int-version-parsing/",
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
	"ruff_code": "RUF048",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "map-int-version-parsing",
	"ruff_since": "0.10.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
