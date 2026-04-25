# SPDX-License-Identifier: Apache-2.0
# Ruff rule S701 (flake8-bandit): jinja2 autoescape false
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s701

import rego.v1

metadata := {
	"id": "RUFF-S701",
	"name": "jinja2 autoescape false",
	"description": "Using jinja2 templates with `autoescape=False` is dangerous and can lead to XSS. Ensure `autoescape=True` or use the `select_autoescape` function.",
	"help_uri": "https://docs.astral.sh/ruff/rules/jinja2-autoescape-false/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S701",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "jinja2-autoescape-false",
	"ruff_since": "v0.0.220",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`jinja2\.Environment\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Jinja2 autoescape not enabled",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
