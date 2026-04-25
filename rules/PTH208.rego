# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH208 (flake8-use-pathlib): os listdir
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth208

import rego.v1

metadata := {
	"id": "RUFF-PTH208",
	"name": "os listdir",
	"description": "Use `pathlib.Path.iterdir()` instead.",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-listdir/",
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
	"ruff_code": "PTH208",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "os-listdir",
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
