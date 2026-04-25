# SPDX-License-Identifier: Apache-2.0
# Ruff rule S506 (flake8-bandit): unsafe yaml load
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s506

import rego.v1

metadata := {
	"id": "RUFF-S506",
	"name": "unsafe yaml load",
	"description": "Probable use of unsafe loader `<value>` with `yaml.load`. Allows instantiation of arbitrary objects. Consider `yaml.safe_load`.",
	"help_uri": "https://docs.astral.sh/ruff/rules/unsafe-yaml-load/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S506",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "unsafe-yaml-load",
	"ruff_since": "v0.0.212",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\byaml\.load\s*\(`, line)
	not regex.match(`.*Loader`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of unsafe yaml.load - use yaml.safe_load instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
