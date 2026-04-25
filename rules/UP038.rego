# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP038 (pyupgrade): non pep604 isinstance
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up038

import rego.v1

metadata := {
	"id": "RUFF-UP038",
	"name": "non pep604 isinstance",
	"description": "Use `X | Y` in `{}` call instead of `(X, Y)`",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-pep604-isinstance/",
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
	"ruff_code": "UP038",
	"ruff_linter": "pyupgrade",
	"ruff_name": "non-pep604-isinstance",
	"ruff_since": "0.13.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`isinstance\s*\(.*Union\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use X | Y in isinstance() call",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
