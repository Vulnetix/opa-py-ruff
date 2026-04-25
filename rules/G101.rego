# SPDX-License-Identifier: Apache-2.0
# Ruff rule G101 (flake8-logging-format): logging extra attr clash
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_g101

import rego.v1

metadata := {
	"id": "RUFF-G101",
	"name": "logging extra attr clash",
	"description": "Logging statement uses an `extra` field that clashes with a `LogRecord` field: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-extra-attr-clash/",
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
	"ruff_code": "G101",
	"ruff_linter": "flake8-logging-format",
	"ruff_name": "logging-extra-attr-clash",
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
