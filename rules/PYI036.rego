# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI036 (flake8-pyi): bad exit annotation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi036

import rego.v1

metadata := {
	"id": "RUFF-PYI036",
	"name": "bad exit annotation",
	"description": "Star-args in `<value>` should be annotated with `object`",
	"help_uri": "https://docs.astral.sh/ruff/rules/bad-exit-annotation/",
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
	"ruff_code": "PYI036",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "bad-exit-annotation",
	"ruff_since": "v0.0.279",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
