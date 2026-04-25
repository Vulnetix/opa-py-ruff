# SPDX-License-Identifier: Apache-2.0
# Ruff rule S311 (flake8-bandit): suspicious non cryptographic random usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s311

import rego.v1

metadata := {
	"id": "RUFF-S311",
	"name": "suspicious non cryptographic random usage",
	"description": "Standard pseudo-random generators are not suitable for cryptographic purposes",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-non-cryptographic-random-usage/",
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
	"ruff_code": "S311",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-non-cryptographic-random-usage",
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
	regex.match(`\brandom\.(random|randint|choice|shuffle|uniform|randrange)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Standard pseudo-random generators not suitable for cryptographic purposes",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
