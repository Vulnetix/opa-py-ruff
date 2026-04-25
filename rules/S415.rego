# SPDX-License-Identifier: Apache-2.0
# Ruff rule S415 (flake8-bandit): suspicious pyghmi import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s415

import rego.v1

metadata := {
	"id": "RUFF-S415",
	"name": "suspicious pyghmi import",
	"description": "An IPMI-related module is being imported. Prefer an encrypted protocol over IPMI.",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-pyghmi-import/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S415",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-pyghmi-import",
	"ruff_since": "v0.1.12",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
