# SPDX-License-Identifier: Apache-2.0
# Ruff rule S112 (flake8-bandit): try except continue
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s112

import rego.v1

metadata := {
	"id": "RUFF-S112",
	"name": "try except continue",
	"description": "`try`-`except`-`continue` detected, consider logging the exception",
	"help_uri": "https://docs.astral.sh/ruff/rules/try-except-continue/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S112",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "try-except-continue",
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
	regex.match(`except\s*:\s*\n\s*continue`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "try-except-continue detected",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
