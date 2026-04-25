# SPDX-License-Identifier: Apache-2.0
# Ruff rule G201 (flake8-logging-format): logging exc info
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_g201

import rego.v1

metadata := {
	"id": "RUFF-G201",
	"name": "logging exc info",
	"description": "Logging `.exception(...)` should be used instead of `.error(..., exc_info=True)`",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-exc-info/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-logging-format", "g"],
	"ruff_code": "G201",
	"ruff_linter": "flake8-logging-format",
	"ruff_name": "logging-exc-info",
	"ruff_since": "v0.0.236",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
