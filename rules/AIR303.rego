# SPDX-License-Identifier: Apache-2.0
# Ruff rule AIR303 (Airflow): airflow3 incompatible function signature
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_air303

import rego.v1

metadata := {
	"id": "RUFF-AIR303",
	"name": "airflow3 incompatible function signature",
	"description": "`<value>` signature is changed in Airflow 3.0",
	"help_uri": "https://docs.astral.sh/ruff/rules/airflow3-incompatible-function-signature/",
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
	"ruff_code": "AIR303",
	"ruff_linter": "Airflow",
	"ruff_name": "airflow3-incompatible-function-signature",
	"ruff_since": "0.14.11",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
