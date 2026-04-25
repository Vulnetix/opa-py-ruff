# SPDX-License-Identifier: Apache-2.0
# Ruff rule S608 (flake8-bandit): hardcoded sql expression
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s608

import rego.v1

metadata := {
	"id": "RUFF-S608",
	"name": "hardcoded sql expression",
	"description": "Possible SQL injection vector through string-based query construction",
	"help_uri": "https://docs.astral.sh/ruff/rules/hardcoded-sql-expression/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S608",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "hardcoded-sql-expression",
	"ruff_since": "v0.0.245",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)(execute|executemany|cursor)\s*\(.*\s*(\+|\.format|f"|f\')`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Possible SQL injection via string concatenation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
