# SPDX-License-Identifier: Apache-2.0
# Ruff rule S503 (flake8-bandit): ssl with bad defaults
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s503

import rego.v1

metadata := {
	"id": "RUFF-S503",
	"name": "ssl with bad defaults",
	"description": "Argument default set to insecure SSL protocol: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/ssl-with-bad-defaults/",
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
	"ruff_code": "S503",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "ssl-with-bad-defaults",
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
	regex.match(`ssl\.OP_NO_SSLv2|ssl\.OP_NO_SSLv3`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Detected disabled SSL/TLS security option",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
