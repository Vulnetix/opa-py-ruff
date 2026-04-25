# SPDX-License-Identifier: Apache-2.0
# Ruff rule S504 (flake8-bandit): ssl with no version
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s504

import rego.v1

metadata := {
	"id": "RUFF-S504",
	"name": "ssl with no version",
	"description": "`ssl.wrap_socket` called without an `ssl_version``",
	"help_uri": "https://docs.astral.sh/ruff/rules/ssl-with-no-version/",
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
	"ruff_code": "S504",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "ssl-with-no-version",
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
	regex.match(`ssl\.OP_NO_TLSv1\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Detected disabled TLSv1 security option",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
