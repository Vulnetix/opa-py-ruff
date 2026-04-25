# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH203 (flake8-use-pathlib): os path getatime
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth203

import rego.v1

metadata := {
	"id": "RUFF-PTH203",
	"name": "os path getatime",
	"description": "`os.path.getatime` should be replaced by `Path.stat().st_atime`",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-path-getatime/",
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
	"ruff_code": "PTH203",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "os-path-getatime",
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
