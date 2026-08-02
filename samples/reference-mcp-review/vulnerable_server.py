#!/usr/bin/env python3
"""Intentionally vulnerable MCP invoice server used only as a review fixture."""

from __future__ import annotations

import asyncio


INVOICES = {
    ("tenant-red", "inv-100"): {"invoice_id": "inv-100", "tenant_id": "tenant-red", "total": 1250},
    ("tenant-blue", "inv-200"): {"invoice_id": "inv-200", "tenant_id": "tenant-blue", "total": 9800},
}


def get_invoice(*, authenticated_tenant: str, tenant_id: str, invoice_id: str) -> dict:
    """VULNERABLE: `authenticated_tenant` is ignored; tenant selection is user input."""
    del authenticated_tenant
    return dict(INVOICES[(tenant_id, invoice_id)])


TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "tenant_id": {"type": "string"},
        "invoice_id": {"type": "string"},
    },
    "required": ["tenant_id", "invoice_id"],
    "additionalProperties": False,
}

def build_server():
    """Build the optional MCP runtime adapter.

    Keeping SDK imports here lets the pinned authorization retest exercise the
    source-level defect with the standard library alone. Running this fixture as
    an MCP server still requires the official MCP Python SDK.
    """
    import mcp.types as types
    from mcp.server.lowlevel import Server

    server = Server("reference-invoice-server-vulnerable", version="1.0.0")

    @server.list_tools()
    async def list_tools():
        return [types.Tool(
            name="get_invoice",
            description="Returns one invoice by tenant and invoice identifier.",
            inputSchema=TOOL_SCHEMA,
        )]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name != "get_invoice":
            raise ValueError("unknown tool")
        # Synthetic wrapper identity. The defect is that the handler ignores it.
        result = get_invoice(
            authenticated_tenant="tenant-red",
            tenant_id=str(arguments["tenant_id"]),
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
