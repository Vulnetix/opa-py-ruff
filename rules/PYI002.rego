# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI002 (flake8-pyi): complex if statement in stub
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi002

import rego.v1

metadata := {
	"id": "RUFF-PYI002",
	"name": "complex if statement in stub",
	"description": "`if` test must be a simple comparison against `sys.platform` or `sys.version_info`",
	"help_uri": "https://docs.astral.sh/ruff/rules/complex-if-statement-in-stub/",
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
	"ruff_code": "PYI002",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "complex-if-statement-in-stub",
	"ruff_since": "v0.0.276",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
