# MCP integration security review — sanitized sample

**Client:** NorthwindPay Reference Integration (fictional)

**Scope:** one invoice MCP server and one stdio host integration

**Reviewed versions:** SHA-256-pinned files in `EVIDENCE-MANIFEST.json`

**Environment:** local synthetic fixture; no production system or customer data

**Status:** illustrative manual-review sample, not a customer engagement

## Executive summary

The vulnerable server permits a tenant-red principal to read tenant-blue's
invoice by choosing `tenant_id` in the MCP tool arguments. This is a confirmed
broken object-level authorization defect, not an automated telemetry finding.
The fixed version removes tenant selection from the public tool schema, derives
tenant identity from the trusted host context, verifies object ownership, and
passes the focused remediation retest.

No claim is made about OAuth, organization-wide tenant isolation, production
deployment configuration, or other application routes. Those were outside this
synthetic fixture's scope.

## Finding MCP-AUTH-001 — caller-controlled tenant selection

**Severity:** High

**Status:** Confirmed in vulnerable version; remediated in fixed version

**Category:** Broken object-level authorization / confused deputy

**Evidence source:** Manual source review and controlled local test

### What was confirmed

`vulnerable_server.get_invoice()` receives both an authenticated tenant and a
caller-controlled tenant, discards the authenticated value, and performs the
lookup with the caller's value. The MCP input schema explicitly exposes
`tenant_id`, making the cross-tenant selector reachable through an ordinary
tool call.

The test `test_vulnerable_version_allows_cross_tenant_read` authenticates as
`tenant-red`, requests `tenant-blue` invoice `inv-200`, and receives the blue
tenant's fabricated record.

### Impact

If this pattern existed in a real multi-tenant service, any principal allowed
to call the tool could attempt to read another tenant's invoices when an
identifier is known or guessed. The fixture does not establish identifier
predictability or production reachability; those would be validated during an
actual engagement.

### Why telemetry alone is insufficient

A normal-looking call to `get_invoice` does not reveal whether the requested
object belongs to the authenticated principal. The MCP telemetry checks can
inventory the tool and capture bounded indicators, but authorization requires
source, configuration, identity-context, and business-rule review.

### Remediation

- Remove tenant or owner selection from untrusted tool arguments.
- Bind the principal and tenant to the authenticated request/host context.
- Apply an ownership predicate in the data lookup, not only in UI or prompt
  instructions.
- Reject unknown object identifiers without revealing cross-tenant existence.
- Add a negative cross-tenant authorization test for every sensitive tool.

### Retest result

The fixed tool schema accepts only `invoice_id`. The implementation looks up
the object under the authenticated tenant and raises `AuthorizationError` when
the object is outside that tenant. The focused test suite passes:

- vulnerable cross-tenant reproduction: succeeds as expected;
- fixed cross-tenant attempt: denied;
- fixed same-tenant request: succeeds;
- fixed schema: no caller-controlled tenant field.

## Checks completed

| Check | Result | Evidence |
|---|---|---|
| Tool schema and handler data flow | Completed | Source review of both pinned files |
| Cross-tenant negative authorization | Failed vulnerable / passed fixed | `tests/test_authorization.py` |
| Same-tenant regression | Passed fixed | `tests/test_authorization.py` |
| Telemetry indicator scan | Not run | Not needed to establish this source-level defect |
| OAuth/remote transport | Unsupported by fixture | Requires a real remote integration |
| Production deployment/configuration | Out of scope | Synthetic local example only |

The machine-readable control result is pinned in `CONTROL-EVIDENCE.json`.
Identity/object authorization, the approved tool manifest, and artifact
integrity are verified for this synthetic fixture. Filesystem and write-action
controls are not applicable. Secret-flow testing is explicitly not tested.
No untested boundary is reported as passing.

## Limitations

This report demonstrates one finding and one focused retest. It is not a full
pentest, compliance assessment, production authorization review, or guarantee
that the fixed pattern is sufficient for a real identity architecture.
