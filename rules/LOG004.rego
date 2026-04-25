# SPDX-License-Identifier: Apache-2.0
# Ruff rule LOG004 (flake8-logging): log exception outside except handler
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_log004

import rego.v1

metadata := {
	"id": "RUFF-LOG004",
	"name": "log exception outside except handler",
	"description": "`.exception()` call outside exception handlers",
	"help_uri": "https://docs.astral.sh/ruff/rules/log-exception-outside-except-handler/",
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
	"ruff_code": "LOG004",
	"ruff_linter": "flake8-logging",
	"ruff_name": "log-exception-outside-except-handler",
	"ruff_since": "0.9.5",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
