# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR001 (Airflow): airflow variable name task id mismatch
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air001

import rego.v1

metadata := {
	"id": "RUFF-AIR001",
	"name": "airflow variable name task id mismatch",
	"description": "Task variable name should match the `task_id`: '<value>'",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow-variable-name-task-id-mismatch/",
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
	"ruff_code": "AIR001",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow-variable-name-task-id-mismatch",
	"ruff_since": "v0.0.271",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
