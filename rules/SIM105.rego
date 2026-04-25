# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM105 (flake8-simplify): suppressible exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim105

import rego.v1

metadata := {
	"id": "RUFF-SIM105",
	"name": "suppressible exception",
	"description": "Use `contextlib.suppress(<value>)` instead of `try`-`except`-`pass`",
	"help_uri": "https://docs.astral.sh/ruff/rules/suppressible-exception/",
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
	"ruff_code": "SIM105",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "suppressible-exception",
	"ruff_since": "v0.0.211",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`try:\s*\n.+\n\s*except\s+\w+:\s*\n\s*pass`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use contextlib.suppress() instead of try-except-pass",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
