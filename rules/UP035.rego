# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP035 (pyupgrade): deprecated import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up035

import rego.v1

metadata := {
	"id": "RUFF-UP035",
	"name": "deprecated import",
	"description": "Import from `<value>` instead: <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/deprecated-import/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP035",
	"ruff_linter": "pyupgrade",
	"ruff_name": "deprecated-import",
	"ruff_since": "v0.0.239",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^from\s+(typing|collections\.abc)\s+import`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Import from deprecated location",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
