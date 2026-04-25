# SPDX-License-Identifier: Apache-2.0
# Ruff rule S502 (flake8-bandit): ssl insecure version
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s502

import rego.v1

metadata := {
	"id": "RUFF-S502",
	"name": "ssl insecure version",
	"description": "Call made with insecure SSL protocol: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/ssl-insecure-version/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S502",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "ssl-insecure-version",
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
	regex.match(`ssl\.PROTOCOL_(SSLv2|SSLv3|TLSv1)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of insecure SSL/TLS version",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
