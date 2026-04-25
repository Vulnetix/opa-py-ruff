# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH211 (flake8-use-pathlib): os symlink
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth211

import rego.v1

metadata := {
	"id": "RUFF-PTH211",
	"name": "os symlink",
	"description": "`os.symlink` should be replaced by `Path.symlink_to`",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-symlink/",
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
	"ruff_code": "PTH211",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "os-symlink",
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
