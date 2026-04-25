# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF035 (Ruff-specific rules): ruff unsafe markup use
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf035

import rego.v1

metadata := {
	"id": "RUFF-RUF035",
	"name": "ruff unsafe markup use",
	"description": "Unsafe use of `<value>` detected",
	"help_uri": "https://docs.astral.sh/ruff/rules/ruff-unsafe-markup-use/",
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
	"ruff_code": "RUF035",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "ruff-unsafe-markup-use",
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
