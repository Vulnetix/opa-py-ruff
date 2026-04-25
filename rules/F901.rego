# SPDX-License-Identifier: Apache-2.0
# Ruff rule F901 (Pyflakes): raise not implemented
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f901

import rego.v1

metadata := {
	"id": "RUFF-F901",
	"name": "raise not implemented",
	"description": "`raise NotImplemented` should be `raise NotImplementedError`",
	"help_uri": "https://docs.astral.sh/ruff/rules/raise-not-implemented/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyflakes", "f"],
	"ruff_code": "F901",
	"ruff_linter": "Pyflakes",
	"ruff_name": "raise-not-implemented",
	"ruff_since": "v0.0.18",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
