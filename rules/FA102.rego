# SPDX-License-Identifier: Apache-2.0
# Ruff rule FA102 (flake8-future-annotations): future required type annotation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_fa102

import rego.v1

metadata := {
	"id": "RUFF-FA102",
	"name": "future required type annotation",
	"description": "Missing `from __future__ import annotations`, but uses <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/future-required-type-annotation/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-future-annotations", "fa"],
	"ruff_code": "FA102",
	"ruff_linter": "flake8-future-annotations",
	"ruff_name": "future-required-type-annotation",
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
