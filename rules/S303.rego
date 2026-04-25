# SPDX-License-Identifier: Apache-2.0
# Ruff rule S303 (flake8-bandit): suspicious insecure hash usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s303

import rego.v1

metadata := {
	"id": "RUFF-S303",
	"name": "suspicious insecure hash usage",
	"description": "Use of insecure MD2, MD4, MD5, or SHA1 hash function",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-insecure-hash-usage/",
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
	"ruff_code": "S303",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-insecure-hash-usage",
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
	regex.match(`\bhashlib\.(md5|sha1)\s*\(|MD5|SHA1`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of MD5 or SHA1 — consider a stronger algorithm",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
