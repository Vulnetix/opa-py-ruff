# SPDX-License-Identifier: Apache-2.0
# Ruff rule S201 (flake8-bandit): flask debug true
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s201

import rego.v1

metadata := {
	"id": "RUFF-S201",
	"name": "flask debug true",
	"description": "Use of `debug=True` in Flask app detected",
	"help_uri": "https://docs.astral.sh/ruff/rules/flask-debug-true/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S201",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "flask-debug-true",
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
	regex.match(`flask\.run\s*\(.*debug\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Flask app run with debug enabled",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
