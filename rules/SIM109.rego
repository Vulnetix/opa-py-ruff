# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM109 (flake8-simplify): compare with tuple
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim109

import rego.v1

metadata := {
	"id": "RUFF-SIM109",
	"name": "compare with tuple",
	"description": "Use `<value>` instead of multiple equality comparisons",
	"help_uri": "https://docs.astral.sh/ruff/rules/compare-with-tuple/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM109",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "compare-with-tuple",
	"ruff_since": "v0.0.213",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`if\s+\w+\s*==\s*\w+\s+or\s+\w+\s*==\s*\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use containment check instead of multiple comparisons",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
