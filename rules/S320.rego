# SPDX-License-Identifier: Apache-2.0
# Ruff rule S320 (flake8-bandit): suspicious xmle tree usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s320

import rego.v1

metadata := {
	"id": "RUFF-S320",
	"name": "suspicious xmle tree usage",
	"description": "Using `lxml` to parse untrusted data is known to be vulnerable to XML attacks",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-xmle-tree-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S320",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-xmle-tree-usage",
	"ruff_since": "0.12.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\blxml\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "lxml is vulnerable to XML attacks by default",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
