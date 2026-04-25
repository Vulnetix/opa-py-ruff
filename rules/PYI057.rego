# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI057 (flake8-pyi): byte string usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi057

import rego.v1

metadata := {
	"id": "RUFF-PYI057",
	"name": "byte string usage",
	"description": "Do not use `<value>.ByteString`, which has unclear semantics and is deprecated",
	"help_uri": "https://docs.astral.sh/ruff/rules/byte-string-usage/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI057",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "byte-string-usage",
	"ruff_since": "0.6.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
