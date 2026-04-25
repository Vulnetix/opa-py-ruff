# SPDX-License-Identifier: Apache-2.0
# Ruff rule S507 (flake8-bandit): ssh no host key verification
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s507

import rego.v1

metadata := {
	"id": "RUFF-S507",
	"name": "ssh no host key verification",
	"description": "Paramiko call with policy set to automatically trust the unknown host key",
	"help_uri": "https://docs.astral.sh/ruff/rules/ssh-no-host-key-verification/",
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
	"ruff_code": "S507",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "ssh-no-host-key-verification",
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
	regex.match(`RejectPolicy|AutoAddPolicy`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Paramiko auto-trust or reject host key policy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
