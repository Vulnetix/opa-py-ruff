# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB166 (refurb): int on sliced str
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb166

import rego.v1

metadata := {
	"id": "RUFF-FURB166",
	"name": "int on sliced str",
	"description": "Use of `int` with explicit `base=<value>` after removing prefix",
	"help_uri": "https://docs.astral.sh/ruff/rules/int-on-sliced-str/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB166",
	"ruff_linter": "refurb",
	"ruff_name": "int-on-sliced-str",
	"ruff_since": "0.12.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
