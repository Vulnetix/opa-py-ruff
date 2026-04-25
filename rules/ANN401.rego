# SPDX-License-Identifier: Apache-2.0
# Ruff rule ANN401 (flake8-annotations): any type
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ann401

import rego.v1

metadata := {
	"id": "RUFF-ANN401",
	"name": "any type",
	"description": "Dynamically typed expressions (typing.Any) are disallowed in `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/any-type/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-annotations", "ann"],
	"ruff_code": "ANN401",
	"ruff_linter": "flake8-annotations",
	"ruff_name": "any-type",
	"ruff_since": "v0.0.108",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
