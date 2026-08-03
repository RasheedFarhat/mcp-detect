from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


vulnerable = load("reference_vulnerable", "vulnerable_server.py")
fixed = load("reference_fixed", "fixed_server.py")


class AuthorizationRetest(unittest.TestCase):
    def test_vulnerable_version_allows_cross_tenant_read(self):
        record = vulnerable.get_invoice(
            authenticated_tenant="tenant-red",
            tenant_id="tenant-blue",
            invoice_id="inv-200",
        )
        self.assertEqual(record["tenant_id"], "tenant-blue")

    def test_fixed_version_rejects_cross_tenant_read(self):
        with self.assertRaises(fixed.AuthorizationError):
            fixed.get_invoice(
                authenticated_tenant="tenant-red",
                invoice_id="inv-200",
            )

    def test_fixed_version_preserves_authorized_access(self):
        record = fixed.get_invoice(
            authenticated_tenant="tenant-red",
            invoice_id="inv-100",
        )
        self.assertEqual(record["tenant_id"], "tenant-red")

    def test_fixed_tool_schema_removes_caller_controlled_tenant(self):
        self.assertNotIn("tenant_id", fixed.TOOL_SCHEMA["properties"])
        self.assertFalse(fixed.TOOL_SCHEMA["additionalProperties"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
