# SPDX-License-Identifier: Apache-2.0
# Ruff rule S321 (flake8-bandit): suspicious ftp lib usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s321

import rego.v1

metadata := {
	"id": "RUFF-S321",
	"name": "suspicious ftp lib usage",
	"description": "FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-ftp-lib-usage/",
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
	"ruff_code": "S321",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-ftp-lib-usage",
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
	regex.match(`\bftplib\b|FTP\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "FTP-related functions are insecure; use SFTP or FTPS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
