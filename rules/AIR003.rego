# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR003 (Airflow): airflow variable get outside task
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air003

import rego.v1

metadata := {
	"id": "RUFF-AIR003",
	"name": "airflow variable get outside task",
	"description": "`Variable.get()` outside of a task",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow-variable-get-outside-task/",
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
	"ruff_code": "AIR003",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow-variable-get-outside-task",
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
