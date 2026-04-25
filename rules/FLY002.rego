# SPDX-License-Identifier: Apache-2.0
# Ruff rule FLY002 (flynt): static join to f string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_fly002

import rego.v1

metadata := {
	"id": "RUFF-FLY002",
	"name": "static join to f string",
	"description": "Consider `<value>` instead of string join",
	"help_uri": "https://docs.astral.sh/ruff/rules/static-join-to-f-string/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flynt", "fly"],
	"ruff_code": "FLY002",
	"ruff_linter": "flynt",
	"ruff_name": "static-join-to-f-string",
	"ruff_since": "v0.0.266",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
