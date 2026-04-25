# SPDX-License-Identifier: Apache-2.0
# Ruff rule TID252 (flake8-tidy-imports): relative imports
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tid252

import rego.v1

metadata := {
	"id": "RUFF-TID252",
	"name": "relative imports",
	"description": "Prefer absolute imports over relative imports from parent modules",
	"help_uri": "https://docs.astral.sh/ruff/rules/relative-imports/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-tidy-imports", "tid"],
	"ruff_code": "TID252",
	"ruff_linter": "flake8-tidy-imports",
	"ruff_name": "relative-imports",
	"ruff_since": "v0.0.169",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^from\s+\.\s+import|^from\s+\.\.\s+import`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Prefer absolute imports over relative imports",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
