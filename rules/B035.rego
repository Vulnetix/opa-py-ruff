# SPDX-License-Identifier: Apache-2.0
# Ruff rule B035 (flake8-bugbear): static key dict comprehension
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b035

import rego.v1

metadata := {
	"id": "RUFF-B035",
	"name": "static key dict comprehension",
	"description": "Dictionary comprehension uses static key: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/static-key-dict-comprehension/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B035",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "static-key-dict-comprehension",
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
	regex.match(`\{[^}]*for\s+\w+\s+in\s+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Static key in dict comprehension",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
