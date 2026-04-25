# SPDX-License-Identifier: Apache-2.0
# Ruff rule S305 (flake8-bandit): suspicious insecure cipher mode usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s305

import rego.v1

metadata := {
	"id": "RUFF-S305",
	"name": "suspicious insecure cipher mode usage",
	"description": "Use of insecure block cipher mode, replace with a known secure mode such as CBC or CTR",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-insecure-cipher-mode-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S305",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-insecure-cipher-mode-usage",
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
	regex.match(`\bModes\.ECB\b|ECB\s*mode`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of ECB mode is insecure",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
