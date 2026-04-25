# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0115 (Pylint): nonlocal and global
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0115

import rego.v1

metadata := {
	"id": "RUFF-PLE0115",
	"name": "nonlocal and global",
	"description": "Name `<value>` is both `nonlocal` and `global`",
	"help_uri": "https://docs.astral.sh/ruff/rules/nonlocal-and-global/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE0115",
	"ruff_linter": "Pylint",
	"ruff_name": "nonlocal-and-global",
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
