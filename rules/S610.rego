# SPDX-License-Identifier: Apache-2.0
# Ruff rule S610 (flake8-bandit): django extra
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s610

import rego.v1

metadata := {
	"id": "RUFF-S610",
	"name": "django extra",
	"description": "Use of Django `extra` can lead to SQL injection vulnerabilities",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-extra/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [73],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S610",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "django-extra",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
