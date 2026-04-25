# SPDX-License-Identifier: Apache-2.0
# Ruff rule PGH005 (pygrep-hooks): invalid mock access
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pgh005

import rego.v1

metadata := {
	"id": "RUFF-PGH005",
	"name": "invalid mock access",
	"description": "Mock method should be called: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-mock-access/",
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
	"ruff_code": "PGH005",
	"ruff_linter": "pygrep-hooks",
	"ruff_name": "invalid-mock-access",
	"ruff_since": "v0.0.266",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`mock\.patch\s*\(.*create=True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Invalid mock.patch.object use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
