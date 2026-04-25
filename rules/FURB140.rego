# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB140 (refurb): reimplemented starmap
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb140

import rego.v1

metadata := {
	"id": "RUFF-FURB140",
	"name": "reimplemented starmap",
	"description": "Use `itertools.starmap` instead of the generator",
	"help_uri": "https://docs.astral.sh/ruff/rules/reimplemented-starmap/",
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
	"ruff_code": "FURB140",
	"ruff_linter": "refurb",
	"ruff_name": "reimplemented-starmap",
	"ruff_since": "v0.0.291",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
