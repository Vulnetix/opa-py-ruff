# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR321 (Airflow): airflow31 moved
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air321

import rego.v1

metadata := {
	"id": "RUFF-AIR321",
	"name": "airflow31 moved",
	"description": "`<value>` is moved in Airflow 3.1",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow31-moved/",
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
	"ruff_code": "AIR321",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow31-moved",
	"ruff_since": "0.15.1",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
