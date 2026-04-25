# SPDX-License-Identifier: Apache-2.0
# Ruff rule S505 (flake8-bandit): weak cryptographic key
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s505

import rego.v1

metadata := {
	"id": "RUFF-S505",
	"name": "weak cryptographic key",
	"description": "<value> key sizes below <value> bits are considered breakable",
	"help_uri": "https://docs.astral.sh/ruff/rules/weak-cryptographic-key/",
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
	"ruff_code": "S505",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "weak-cryptographic-key",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`key_size\s*[<]=\s*(512|1024)|RSA\s*\(\s*(512|1024)\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Weak cryptographic key",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
