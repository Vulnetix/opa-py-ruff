# SPDX-License-Identifier: Apache-2.0
# Ruff rule DJ006 (flake8-django): django exclude with model form
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dj006

import rego.v1

metadata := {
	"id": "RUFF-DJ006",
	"name": "django exclude with model form",
	"description": "Do not use `exclude` with `ModelForm`, use `fields` instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-exclude-with-model-form/",
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
	"ruff_code": "DJ006",
	"ruff_linter": "flake8-django",
	"ruff_name": "django-exclude-with-model-form",
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
	regex.match(`exclude\s*=\s*__all__\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not use exclude with ModelForm",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
