# SPDX-License-Identifier: Apache-2.0
# Ruff rule S304 (flake8-bandit): suspicious insecure cipher usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s304

import rego.v1

metadata := {
	"id": "RUFF-S304",
	"name": "suspicious insecure cipher usage",
	"description": "Use of insecure cipher, replace with a known secure cipher such as AES",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-insecure-cipher-usage/",
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
	"ruff_code": "S304",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-insecure-cipher-usage",
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
	regex.match(`\bCipher\b.*\b(DES|RC2|RC4|Blowfish|ARC4)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of weak cipher",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
