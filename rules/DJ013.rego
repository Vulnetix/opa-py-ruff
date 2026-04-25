# SPDX-License-Identifier: Apache-2.0
# Ruff rule DJ013 (flake8-django): django non leading receiver decorator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dj013

import rego.v1

metadata := {
	"id": "RUFF-DJ013",
	"name": "django non leading receiver decorator",
	"description": "`@receiver` decorator must be on top of all the other decorators",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-non-leading-receiver-decorator/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-django", "dj"],
	"ruff_code": "DJ013",
	"ruff_linter": "flake8-django",
	"ruff_name": "django-non-leading-receiver-decorator",
	"ruff_since": "v0.0.246",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
