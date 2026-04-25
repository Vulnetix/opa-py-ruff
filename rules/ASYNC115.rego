# SPDX-License-Identifier: Apache-2.0
# Ruff rule ASYNC115 (flake8-async): async zero sleep
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_async115

import rego.v1

metadata := {
	"id": "RUFF-ASYNC115",
	"name": "async zero sleep",
	"description": "Use `<value>.lowlevel.checkpoint()` instead of `<value>.sleep(0)`",
	"help_uri": "https://docs.astral.sh/ruff/rules/async-zero-sleep/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-async", "async"],
	"ruff_code": "ASYNC115",
	"ruff_linter": "flake8-async",
	"ruff_name": "async-zero-sleep",
	"ruff_since": "0.5.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`asyncio\.sleep\s*\(\s*0\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "asyncio.sleep(0) is a no-op",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
