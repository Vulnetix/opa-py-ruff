# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR004 (Airflow): airflow task branch as short circuit
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air004

import rego.v1

metadata := {
	"id": "RUFF-AIR004",
	"name": "airflow task branch as short circuit",
	"description": "`@task.branch` can be replaced with `@task.short_circuit`",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow-task-branch-as-short-circuit/",
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
	"ruff_code": "AIR004",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow-task-branch-as-short-circuit",
	"ruff_since": "0.15.12",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
