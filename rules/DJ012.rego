# SPDX-License-Identifier: Apache-2.0
# Ruff rule DJ012 (flake8-django): django unordered body content in model
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dj012

import rego.v1

metadata := {
	"id": "RUFF-DJ012",
	"name": "django unordered body content in model",
	"description": "Order of model's inner classes, methods, and fields does not follow the Django Style Guide: <value> should come before <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-unordered-body-content-in-model/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-django", "dj"],
	"ruff_code": "DJ012",
	"ruff_linter": "flake8-django",
	"ruff_name": "django-unordered-body-content-in-model",
	"ruff_since": "v0.0.258",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`class\s+\w+.*Model.*:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Order of Model fields",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
