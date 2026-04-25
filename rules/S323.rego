# SPDX-License-Identifier: Apache-2.0
# Ruff rule S323 (flake8-bandit): suspicious unverified context usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s323

import rego.v1

metadata := {
	"id": "RUFF-S323",
	"name": "suspicious unverified context usage",
	"description": "Python allows using an insecure context via the `_create_unverified_context` that reverts to the previous behavior that does not validate certificates or perform hostname checks.",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-unverified-context-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S323",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-unverified-context-usage",
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
	regex.match(`ssl\._create_unverified_context\b|CERT_NONE\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SSL/TLS with unverified context",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
