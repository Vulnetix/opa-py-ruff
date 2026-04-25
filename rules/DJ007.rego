# SPDX-License-Identifier: Apache-2.0
# Ruff rule DJ007 (flake8-django): django all with model form
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dj007

import rego.v1

metadata := {
	"id": "RUFF-DJ007",
	"name": "django all with model form",
	"description": "Do not use `__all__` with `ModelForm`, use `fields` instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-all-with-model-form/",
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
	"ruff_code": "DJ007",
	"ruff_linter": "flake8-django",
	"ruff_name": "django-all-with-model-form",
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
	regex.match(`fields\s*=\s*["\']__all__["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not use __all__ with ModelForm",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
