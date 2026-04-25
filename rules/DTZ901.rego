# SPDX-License-Identifier: Apache-2.0
# Ruff rule DTZ901 (flake8-datetimez): datetime min max
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dtz901

import rego.v1

metadata := {
	"id": "RUFF-DTZ901",
	"name": "datetime min max",
	"description": "Use of `datetime.datetime.<value>` without timezone information",
	"help_uri": "https://docs.astral.sh/ruff/rules/datetime-min-max/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-datetimez", "dtz"],
	"ruff_code": "DTZ901",
	"ruff_linter": "flake8-datetimez",
	"ruff_name": "datetime-min-max",
	"ruff_since": "0.10.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
