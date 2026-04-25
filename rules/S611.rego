# SPDX-License-Identifier: Apache-2.0
# Ruff rule S611 (flake8-bandit): django raw sql
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s611

import rego.v1

metadata := {
	"id": "RUFF-S611",
	"name": "django raw sql",
	"description": "Use of `RawSQL` can lead to SQL injection vulnerabilities",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-raw-sql/",
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
	"ruff_code": "S611",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "django-raw-sql",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
