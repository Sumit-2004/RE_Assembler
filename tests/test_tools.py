import os
import tempfile
import unittest

import pefile

from dll_analyzer import tools

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
KERNEL32 = os.path.join(SYSTEM_ROOT, "System32", "kernel32.dll")
DOTNET_MSCORLIB = os.path.join(SYSTEM_ROOT, "Microsoft.NET", "Framework64", "v4.0.30319", "mscorlib.dll")


class TriageTests(unittest.TestCase):
    def test_native_x64_dll(self):
        info = tools.triage_dll(KERNEL32)
        self.assertEqual(info["arch"], "x64")
        self.assertTrue(info["is_dll"])
        self.assertEqual(info["runtime"], "native")
        self.assertTrue(info["aslr"])
        self.assertTrue(info["dep"])
        self.assertEqual(len(info["sha256"]), 64)
        self.assertGreater(info["export_count"], 100)
        self.assertGreater(info["import_count"], 0)
        self.assertTrue(info["entry_point"].startswith("0x"))

    @unittest.skipUnless(os.path.exists(DOTNET_MSCORLIB), ".NET Framework not installed")
    def test_dotnet_dll_is_routed_to_managed_branch(self):
        self.assertEqual(tools.triage_dll(DOTNET_MSCORLIB)["runtime"], ".NET")

    def test_non_pe_file_is_rejected(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as fh:
            fh.write(b"not a portable executable" * 10)
        self.addCleanup(os.remove, fh.name)
        with self.assertRaises(pefile.PEFormatError):
            tools.triage_dll(fh.name)


class ExportTests(unittest.TestCase):
    def test_exports_have_hex_addresses(self):
        exports = tools.list_exports(KERNEL32)
        self.assertTrue(exports)
        for item in exports:
            self.assertTrue(item["address"].startswith("0x"))

    def test_name_filter_is_case_insensitive(self):
        names = [e["name"] for e in tools.list_exports(KERNEL32, "createfile")]
        self.assertIn("CreateFileW", names)
        self.assertTrue(all("createfile" in n.lower() for n in names))


class ImportTests(unittest.TestCase):
    def test_imports_have_expected_fields(self):
        imports = tools.list_imports(KERNEL32)
        self.assertTrue(imports)
        for item in imports:
            self.assertEqual(set(item), {"dll", "delay_load", "function", "iat_address"})
            self.assertTrue(item["iat_address"].startswith("0x"))

    def test_dll_filter_restricts_results(self):
        imports = tools.list_imports(KERNEL32, "ntdll")
        self.assertTrue(imports)
        self.assertTrue(all("ntdll" in i["dll"].lower() for i in imports))


if __name__ == "__main__":
    unittest.main()
