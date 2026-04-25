# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF200 (Ruff-specific rules): invalid pyproject toml
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf200

import rego.v1

metadata := {
	"id": "RUFF-RUF200",
	"name": "invalid pyproject toml",
	"description": "Failed to parse pyproject.toml: <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-pyproject-toml/",
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
	"ruff_code": "RUF200",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "invalid-pyproject-toml",
	"ruff_since": "v0.0.271",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
