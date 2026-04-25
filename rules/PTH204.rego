# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH204 (flake8-use-pathlib): os path getmtime
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth204

import rego.v1

metadata := {
	"id": "RUFF-PTH204",
	"name": "os path getmtime",
	"description": "`os.path.getmtime` should be replaced by `Path.stat().st_mtime`",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-path-getmtime/",
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
	"ruff_code": "PTH204",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "os-path-getmtime",
	"ruff_since": "v0.0.279",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
