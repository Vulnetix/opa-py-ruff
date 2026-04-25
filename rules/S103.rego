# SPDX-License-Identifier: Apache-2.0
# Ruff rule S103 (flake8-bandit): bad file permissions
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s103

import rego.v1

metadata := {
	"id": "RUFF-S103",
	"name": "bad file permissions",
	"description": "`os.chmod` setting a permissive mask `<value>` on file or directory",
	"help_uri": "https://docs.astral.sh/ruff/rules/bad-file-permissions/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S103",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "bad-file-permissions",
	"ruff_since": "v0.0.211",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`os\.chmod\s*\(.+,\s*0o?[0-7]*[2367][0-7]{0,2}\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Permissive file permissions set",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
