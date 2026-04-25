# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI032 (flake8-pyi): any eq ne annotation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi032

import rego.v1

metadata := {
	"id": "RUFF-PYI032",
	"name": "any eq ne annotation",
	"description": "Prefer `object` to `Any` for the second parameter to `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/any-eq-ne-annotation/",
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
	"ruff_code": "PYI032",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "any-eq-ne-annotation",
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
