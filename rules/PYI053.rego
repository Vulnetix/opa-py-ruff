# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI053 (flake8-pyi): string or bytes too long
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi053

import rego.v1

metadata := {
	"id": "RUFF-PYI053",
	"name": "string or bytes too long",
	"description": "String and bytes literals longer than 50 characters are not permitted",
	"help_uri": "https://docs.astral.sh/ruff/rules/string-or-bytes-too-long/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI053",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "string-or-bytes-too-long",
	"ruff_since": "v0.0.271",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
