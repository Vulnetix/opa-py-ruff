# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM116 (flake8-simplify): if else block instead of dict lookup
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim116

import rego.v1

metadata := {
	"id": "RUFF-SIM116",
	"name": "if else block instead of dict lookup",
	"description": "Use a dictionary instead of consecutive `if` statements",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-else-block-instead-of-dict-lookup/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM116",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "if-else-block-instead-of-dict-lookup",
	"ruff_since": "v0.0.250",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`if\s+\w+\s*==\s*["\'].+["\']:\s*\n\s+\w+\s*=\s*.+(\n.*)+elif\s+\w+\s*==`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use dictionary instead of if-elif chain",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
