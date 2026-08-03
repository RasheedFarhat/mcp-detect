# Reference MCP integration review

> **Synthetic reference — not customer work.**

This self-contained fixture demonstrates how source and configuration review
can find an authorization defect that telemetry indicator rules cannot prove.

The vulnerable and fixed servers expose the same fictional invoice lookup.
The vulnerable version trusts a caller-controlled `tenant_id`; the fixed
version takes tenant identity from a trusted host context and checks ownership
before returning data. All invoice data and identifiers are fabricated.

## Run the retest

From the repository root:

```sh
.venv/bin/python3 -m unittest discover \
  -s examples/reference-mcp-review/tests -p 'test_*.py' -v
```

The test suite proves the vulnerable cross-tenant read succeeds, the fixed
version rejects it, normal same-tenant access still works, and the fixed MCP
tool schema no longer accepts a tenant selector.

## Evidence

- `vulnerable_server.py` — intentionally vulnerable implementation.
- `fixed_server.py` — remediated implementation.
- `tests/test_authorization.py` — executable reproduction and retest.
- `CONTROL-EVIDENCE.json`: preventive-control results that do not turn untested boundaries into passes.
- `EVIDENCE-MANIFEST.json` — SHA-256 pins for the reviewed files.
- `MANUAL-REVIEW-SAMPLE.md` — synthetic analyst report.

The environment-variable host context in the fixed stdio wrapper is only a
small model of an authenticated host adapter. A real deployment must verify
how its remote transport authenticates a principal and binds it to a tenant;
this fixture does not claim to solve OAuth or identity architecture.
