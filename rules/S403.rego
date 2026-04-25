# SPDX-License-Identifier: Apache-2.0
# Ruff rule S403 (flake8-bandit): suspicious pickle import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s403

import rego.v1

metadata := {
	"id": "RUFF-S403",
	"name": "suspicious pickle import",
	"description": "`pickle`, `cPickle`, `dill`, and `shelve` modules are possibly insecure",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-pickle-import/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S403",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-pickle-import",
	"ruff_since": "v0.1.12",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^import\s+pickle\b|^from\s+pickle\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Consider using json instead of pickle",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
