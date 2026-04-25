# SPDX-License-Identifier: Apache-2.0
# Ruff rule PGH004 (pygrep-hooks): blanket noqa
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pgh004

import rego.v1

metadata := {
	"id": "RUFF-PGH004",
	"name": "blanket noqa",
	"description": "Use specific rule codes when using `noqa`",
	"help_uri": "https://docs.astral.sh/ruff/rules/blanket-noqa/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pygrep-hooks", "pgh"],
	"ruff_code": "PGH004",
	"ruff_linter": "pygrep-hooks",
	"ruff_name": "blanket-noqa",
	"ruff_since": "v0.0.200",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`#\s*noqa:\s*\w`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use specific rule codes with noqa",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
