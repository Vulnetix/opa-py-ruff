# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI046 (flake8-pyi): unused private protocol
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi046

import rego.v1

metadata := {
	"id": "RUFF-PYI046",
	"name": "unused private protocol",
	"description": "Private protocol `<value>` is never used",
	"help_uri": "https://docs.astral.sh/ruff/rules/unused-private-protocol/",
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
	"ruff_code": "PYI046",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "unused-private-protocol",
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
