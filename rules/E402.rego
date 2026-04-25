# SPDX-License-Identifier: Apache-2.0
# Ruff rule E402 (pycodestyle): module import not at top of file
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e402

import rego.v1

metadata := {
	"id": "RUFF-E402",
	"name": "module import not at top of file",
	"description": "Module level import not at top of cell",
	"help_uri": "https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E402",
	"ruff_linter": "pycodestyle",
	"ruff_name": "module-import-not-at-top-of-file",
	"ruff_since": "v0.0.28",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
