# SPDX-License-Identifier: Apache-2.0
# Ruff rule S324 (flake8-bandit): hashlib insecure hash function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s324

import rego.v1

metadata := {
	"id": "RUFF-S324",
	"name": "hashlib insecure hash function",
	"description": "Probable use of insecure hash functions in `<value>`: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/hashlib-insecure-hash-function/",
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
	"ruff_code": "S324",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "hashlib-insecure-hash-function",
	"ruff_since": "v0.0.212",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bhashlib\.(md5|sha1)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Probable use of insecure hash function",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
