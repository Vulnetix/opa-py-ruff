# SPDX-License-Identifier: Apache-2.0
# Ruff rule S702 (flake8-bandit): mako templates
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s702

import rego.v1

metadata := {
	"id": "RUFF-S702",
	"name": "mako templates",
	"description": "Mako templates allow HTML and JavaScript rendering by default and are inherently open to XSS attacks",
	"help_uri": "https://docs.astral.sh/ruff/rules/mako-templates/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S702",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "mako-templates",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`mako\.template\.Template\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Mako templates without sandboxing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
