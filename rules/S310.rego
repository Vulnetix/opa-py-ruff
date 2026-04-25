# SPDX-License-Identifier: Apache-2.0
# Ruff rule S310 (flake8-bandit): suspicious url open usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s310

import rego.v1

metadata := {
	"id": "RUFF-S310",
	"name": "suspicious url open usage",
	"description": "Audit URL open for permitted schemes. Allowing use of `file:` or custom schemes is often unexpected.",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-url-open-usage/",
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
	"ruff_code": "S310",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-url-open-usage",
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
	regex.match(`\burllib\b.*\bopen\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Audit URL open for permitted schemes",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
