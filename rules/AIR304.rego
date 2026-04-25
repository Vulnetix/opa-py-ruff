# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR304 (Airflow): airflow3 dag dynamic value
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air304

import rego.v1

metadata := {
	"id": "RUFF-AIR304",
	"name": "airflow3 dag dynamic value",
	"description": "`<value>()` produces a value that changes at runtime; using it in a Dag or task argument causes infinite Dag version creation",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow3-dag-dynamic-value/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "airflow", "air"],
	"ruff_code": "AIR304",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow3-dag-dynamic-value",
	"ruff_since": "0.15.6",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
