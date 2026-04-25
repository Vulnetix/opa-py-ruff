# SPDX-License-Identifier: Apache-2.0
# Ruff rule S312 (flake8-bandit): suspicious telnet usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s312

import rego.v1

metadata := {
	"id": "RUFF-S312",
	"name": "suspicious telnet usage",
	"description": "Telnet is considered insecure. Use SSH or some other encrypted protocol.",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-telnet-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [330],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S312",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-telnet-usage",
	"ruff_since": "v0.0.258",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\btelnetlib\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Telnet is considered insecure",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
