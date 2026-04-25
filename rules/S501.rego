# SPDX-License-Identifier: Apache-2.0
# Ruff rule S501 (flake8-bandit): request with no cert validation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s501

import rego.v1

metadata := {
	"id": "RUFF-S501",
	"name": "request with no cert validation",
	"description": "Probable use of `<value>` call with `verify=False` disabling SSL certificate checks",
	"help_uri": "https://docs.astral.sh/ruff/rules/request-with-no-cert-validation/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S501",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "request-with-no-cert-validation",
	"ruff_since": "v0.0.213",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`verify\s*=\s*False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Requests SSL certificate verification disabled",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
