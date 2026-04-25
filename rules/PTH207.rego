# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH207 (flake8-use-pathlib): glob
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth207

import rego.v1

metadata := {
	"id": "RUFF-PTH207",
	"name": "glob",
	"description": "Replace `<value>` with `Path.glob` or `Path.rglob`",
	"help_uri": "https://docs.astral.sh/ruff/rules/glob/",
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
	"ruff_code": "PTH207",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "glob",
	"ruff_since": "v0.0.281",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
