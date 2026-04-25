# SPDX-License-Identifier: Apache-2.0
# Ruff rule S307 (flake8-bandit): suspicious eval usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s307

import rego.v1

metadata := {
	"id": "RUFF-S307",
	"name": "suspicious eval usage",
	"description": "Use of possibly insecure function; consider using `ast.literal_eval`",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-eval-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S307",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-eval-usage",
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
	regex.match(`\beval\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of possibly insecure function - eval",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
