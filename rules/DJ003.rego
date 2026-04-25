# SPDX-License-Identifier: Apache-2.0
# Ruff rule DJ003 (flake8-django): django locals in render function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dj003

import rego.v1

metadata := {
	"id": "RUFF-DJ003",
	"name": "django locals in render function",
	"description": "Avoid passing `locals()` as context to a `render` function",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-locals-in-render-function/",
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
	"ruff_code": "DJ003",
	"ruff_linter": "flake8-django",
	"ruff_name": "django-locals-in-render-function",
	"ruff_since": "v0.0.253",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`models\.ManyToManyField.*through`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid using locals() in render",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
