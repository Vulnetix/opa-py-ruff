# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB157 (refurb): verbose decimal constructor
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb157

import rego.v1

metadata := {
	"id": "RUFF-FURB157",
	"name": "verbose decimal constructor",
	"description": "Verbose expression in `Decimal` constructor",
	"help_uri": "https://docs.astral.sh/ruff/rules/verbose-decimal-constructor/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB157",
	"ruff_linter": "refurb",
	"ruff_name": "verbose-decimal-constructor",
	"ruff_since": "0.12.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Decimal\s*\(\s*["\']\d+["\']\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use Decimal(n) instead of Decimal("n")",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
