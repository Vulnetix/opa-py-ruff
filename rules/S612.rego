# SPDX-License-Identifier: Apache-2.0
# Ruff rule S612 (flake8-bandit): logging config insecure listen
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s612

import rego.v1

metadata := {
	"id": "RUFF-S612",
	"name": "logging config insecure listen",
	"description": "Use of insecure `logging.config.listen` detected",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-config-insecure-listen/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S612",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "logging-config-insecure-listen",
	"ruff_since": "v0.0.231",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
