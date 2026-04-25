# SPDX-License-Identifier: Apache-2.0
# Ruff rule BLE001 (flake8-blind-except): blind except
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ble001

import rego.v1

metadata := {
	"id": "RUFF-BLE001",
	"name": "blind except",
	"description": "Do not catch blind exception: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/blind-except/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-blind-except", "ble"],
	"ruff_code": "BLE001",
	"ruff_linter": "flake8-blind-except",
	"ruff_name": "blind-except",
	"ruff_since": "v0.0.127",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`except\s+BaseException\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Catching BaseException is too broad",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
