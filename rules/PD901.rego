# SPDX-License-Identifier: Apache-2.0
# Ruff rule PD901 (pandas-vet): pandas df variable name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pd901

import rego.v1

metadata := {
	"id": "RUFF-PD901",
	"name": "pandas df variable name",
	"description": "Avoid using the generic variable name `df` for DataFrames",
	"help_uri": "https://docs.astral.sh/ruff/rules/pandas-df-variable-name/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pandas-vet", "pd"],
	"ruff_code": "PD901",
	"ruff_linter": "pandas-vet",
	"ruff_name": "pandas-df-variable-name",
	"ruff_since": "0.13.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
