# SPDX-License-Identifier: Apache-2.0
# Ruff rule DJ001 (flake8-django): django nullable model string field
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dj001

import rego.v1

metadata := {
	"id": "RUFF-DJ001",
	"name": "django nullable model string field",
	"description": "Avoid using `null=True` on string-based fields such as `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/django-nullable-model-string-field/",
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
	"ruff_code": "DJ001",
	"ruff_linter": "flake8-django",
	"ruff_name": "django-nullable-model-string-field",
	"ruff_since": "v0.0.246",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`models\.TextField\s*\(\s*null\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid null=True on TextField",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
