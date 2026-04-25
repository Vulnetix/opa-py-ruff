# SPDX-License-Identifier: Apache-2.0
# Ruff rule S704 (flake8-bandit): unsafe markup use
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s704

import rego.v1

metadata := {
	"id": "RUFF-S704",
	"name": "unsafe markup use",
	"description": "Unsafe use of `<value>` detected",
	"help_uri": "https://docs.astral.sh/ruff/rules/unsafe-markup-use/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S704",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "unsafe-markup-use",
	"ruff_since": "0.10.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
