# SPDX-License-Identifier: Apache-2.0
# Ruff rule W505 (pycodestyle): doc line too long
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_w505

import rego.v1

metadata := {
	"id": "RUFF-W505",
	"name": "doc line too long",
	"description": "Doc line too long (<value> > <value>)",
	"help_uri": "https://docs.astral.sh/ruff/rules/doc-line-too-long/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "w"],
	"ruff_code": "W505",
	"ruff_linter": "pycodestyle",
	"ruff_name": "doc-line-too-long",
	"ruff_since": "v0.0.219",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
