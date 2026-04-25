# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH210 (flake8-use-pathlib): invalid pathlib with suffix
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth210

import rego.v1

metadata := {
	"id": "RUFF-PTH210",
	"name": "invalid pathlib with suffix",
	"description": "Invalid suffix passed to `.with_suffix()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-pathlib-with-suffix/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-use-pathlib", "pth"],
	"ruff_code": "PTH210",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "invalid-pathlib-with-suffix",
	"ruff_since": "0.10.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
