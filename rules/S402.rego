# SPDX-License-Identifier: Apache-2.0
# Ruff rule S402 (flake8-bandit): suspicious ftplib import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s402

import rego.v1

metadata := {
	"id": "RUFF-S402",
	"name": "suspicious ftplib import",
	"description": "`ftplib` and related modules are considered insecure. Use SSH, SFTP, SCP, or another encrypted protocol.",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-ftplib-import/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S402",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-ftplib-import",
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
	regex.match(`^import\s+ftplib\b|^from\s+ftplib\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "An FTP-related module is imported",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
