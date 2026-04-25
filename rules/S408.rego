# SPDX-License-Identifier: Apache-2.0
# Ruff rule S408 (flake8-bandit): suspicious xml minidom import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s408

import rego.v1

metadata := {
	"id": "RUFF-S408",
	"name": "suspicious xml minidom import",
	"description": "`xml.dom.minidom` is vulnerable to XML attacks",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-xml-minidom-import/",
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
	"ruff_code": "S408",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-xml-minidom-import",
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
