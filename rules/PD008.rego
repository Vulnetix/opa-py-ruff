# SPDX-License-Identifier: Apache-2.0
# Ruff rule PD008 (pandas-vet): pandas use of dot at
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pd008

import rego.v1

metadata := {
	"id": "RUFF-PD008",
	"name": "pandas use of dot at",
	"description": "Use `.loc` instead of `.at`. If speed is important, use NumPy.",
	"help_uri": "https://docs.astral.sh/ruff/rules/pandas-use-of-dot-at/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pandas-vet", "pd"],
	"ruff_code": "PD008",
	"ruff_linter": "pandas-vet",
	"ruff_name": "pandas-use-of-dot-at",
	"ruff_since": "v0.0.188",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.iat\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use .iloc instead of .iat",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
