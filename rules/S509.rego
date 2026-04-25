# SPDX-License-Identifier: Apache-2.0
# Ruff rule S509 (flake8-bandit): snmp weak cryptography
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s509

import rego.v1

metadata := {
	"id": "RUFF-S509",
	"name": "snmp weak cryptography",
	"description": "You should not use SNMPv3 without encryption. `noAuthNoPriv` & `authNoPriv` is insecure.",
	"help_uri": "https://docs.astral.sh/ruff/rules/snmp-weak-cryptography/",
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
	"ruff_code": "S509",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "snmp-weak-cryptography",
	"ruff_since": "v0.0.218",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
