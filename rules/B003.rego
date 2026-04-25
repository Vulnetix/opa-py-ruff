# SPDX-License-Identifier: Apache-2.0
# Ruff rule B003 (flake8-bugbear): assignment to os environ
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b003

import rego.v1

metadata := {
	"id": "RUFF-B003",
	"name": "assignment to os environ",
	"description": "Assigning to `os.environ` doesn't clear the environment",
	"help_uri": "https://docs.astral.sh/ruff/rules/assignment-to-os-environ/",
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
	"ruff_code": "B003",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "assignment-to-os-environ",
	"ruff_since": "v0.0.102",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`os\.environ\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "os.environ is a mutable mapping - prefer os.getenv",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
