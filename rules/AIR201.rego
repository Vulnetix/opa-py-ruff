# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR201 (Airflow): airflow xcom pull in template string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air201

import rego.v1

metadata := {
	"id": "RUFF-AIR201",
	"name": "airflow xcom pull in template string",
	"description": "Use the `.output` attribute on the task object for '<value>' instead of `xcom_pull` in a template string",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow-xcom-pull-in-template-string/",
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
	"ruff_code": "AIR201",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow-xcom-pull-in-template-string",
	"ruff_since": "0.15.11",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
