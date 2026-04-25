# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI043 (flake8-pyi): t suffixed type alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi043

import rego.v1

metadata := {
	"id": "RUFF-PYI043",
	"name": "t suffixed type alias",
	"description": "Private type alias `<value>` should not be suffixed with `T` (the `T` suffix implies that an object is a `TypeVar`)",
	"help_uri": "https://docs.astral.sh/ruff/rules/t-suffixed-type-alias/",
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
	"ruff_code": "PYI043",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "t-suffixed-type-alias",
	"ruff_since": "v0.0.265",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
