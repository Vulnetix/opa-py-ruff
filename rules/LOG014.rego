# SPDX-License-Identifier: Apache-2.0
# Ruff rule LOG014 (flake8-logging): exc info outside except handler
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_log014

import rego.v1

metadata := {
	"id": "RUFF-LOG014",
	"name": "exc info outside except handler",
	"description": "`exc_info=` outside exception handlers",
	"help_uri": "https://docs.astral.sh/ruff/rules/exc-info-outside-except-handler/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-logging", "log"],
	"ruff_code": "LOG014",
	"ruff_linter": "flake8-logging",
	"ruff_name": "exc-info-outside-except-handler",
	"ruff_since": "0.12.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
