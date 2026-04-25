# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR002 (Airflow): airflow dag no schedule argument
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air002

import rego.v1

metadata := {
	"id": "RUFF-AIR002",
	"name": "airflow dag no schedule argument",
	"description": "`DAG` or `@dag` should have an explicit `schedule` argument",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow-dag-no-schedule-argument/",
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
	"ruff_code": "AIR002",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow-dag-no-schedule-argument",
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
