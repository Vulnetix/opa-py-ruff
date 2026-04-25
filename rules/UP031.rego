# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP031 (pyupgrade): printf string formatting
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up031

import rego.v1

metadata := {
	"id": "RUFF-UP031",
	"name": "printf string formatting",
	"description": "Use format specifiers instead of percent format",
	"help_uri": "https://docs.astral.sh/ruff/rules/printf-string-formatting/",
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
	"ruff_code": "UP031",
	"ruff_linter": "pyupgrade",
	"ruff_name": "printf-string-formatting",
	"ruff_since": "v0.0.229",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`%\s*\(?\s*\w`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use format specifiers instead of % printf-style formatting",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
