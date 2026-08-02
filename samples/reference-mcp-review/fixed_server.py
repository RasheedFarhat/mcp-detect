#!/usr/bin/env python3
"""Remediated MCP invoice server used only as a review fixture."""

from __future__ import annotations

import asyncio
import os


INVOICES = {
    ("tenant-red", "inv-100"): {"invoice_id": "inv-100", "tenant_id": "tenant-red", "total": 1250},
    ("tenant-blue", "inv-200"): {"invoice_id": "inv-200", "tenant_id": "tenant-blue", "total": 9800},
}


class AuthorizationError(PermissionError):
    """The authenticated tenant does not own the requested object."""


def get_invoice(*, authenticated_tenant: str, invoice_id: str) -> dict:
    """Derive the object lookup from trusted identity and verify ownership."""
    record = INVOICES.get((authenticated_tenant, invoice_id))
    if record is None or record["tenant_id"] != authenticated_tenant:
        raise AuthorizationError("invoice is not accessible to this tenant")
    return dict(record)


TOOL_SCHEMA = {
    "type": "object",
    "properties": {"invoice_id": {"type": "string"}},
    "required": ["invoice_id"],
    "additionalProperties": False,
}

def build_server():
    """Build the optional MCP runtime adapter.

    Keeping SDK imports here lets the pinned authorization retest exercise the
    remediation with the standard library alone. Running this fixture as an MCP
    server still requires the official MCP Python SDK.
    """
    import mcp.types as types
    from mcp.server.lowlevel import Server

    server = Server("reference-invoice-server-fixed", version="1.0.1")

    @server.list_tools()
    async def list_tools():
        return [types.Tool(
            name="get_invoice",
            description="Returns an invoice owned by the authenticated tenant.",
            inputSchema=TOOL_SCHEMA,
        )]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name != "get_invoice":
            raise ValueError("unknown tool")
        # Models identity supplied by the trusted host adapter. A production
        # remote server must bind this value to its authenticated request context.
        authenticated_tenant = os.environ.get("MCP_REVIEW_TENANT", "tenant-red")
        result = get_invoice(
            authenticated_tenant=authenticated_tenant,
            invoice_id=str(arguments["invoice_id"]),
        )
        return [types.TextContent(type="text", text=str(result))]

    return server


async def main() -> None:
    from mcp.server.stdio import stdio_server

    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
