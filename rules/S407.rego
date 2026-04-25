# SPDX-License-Identifier: Apache-2.0
# Ruff rule S407 (flake8-bandit): suspicious xml expat import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s407

import rego.v1

metadata := {
	"id": "RUFF-S407",
	"name": "suspicious xml expat import",
	"description": "`xml.dom.expatbuilder` is vulnerable to XML attacks",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-xml-expat-import/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S407",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-xml-expat-import",
	"ruff_since": "v0.1.12",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
