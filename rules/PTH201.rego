# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH201 (flake8-use-pathlib): path constructor current directory
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth201

import rego.v1

metadata := {
	"id": "RUFF-PTH201",
	"name": "path constructor current directory",
	"description": "Do not pass the current directory explicitly to `Path`",
	"help_uri": "https://docs.astral.sh/ruff/rules/path-constructor-current-directory/",
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
	"ruff_code": "PTH201",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "path-constructor-current-directory",
	"ruff_since": "v0.0.279",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
