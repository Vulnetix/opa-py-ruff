# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI059 (flake8-pyi): generic not last base class
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi059

import rego.v1

metadata := {
	"id": "RUFF-PYI059",
	"name": "generic not last base class",
	"description": "`Generic[]` should always be the last base class",
	"help_uri": "https://docs.astral.sh/ruff/rules/generic-not-last-base-class/",
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
	"ruff_code": "PYI059",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "generic-not-last-base-class",
	"ruff_since": "0.13.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
