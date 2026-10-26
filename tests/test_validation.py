"""Backend-free tests for the hallucination-control and evidence logic.

These exercise the parts that must work before any model or disassembler is
trusted: the name check, the evidence log, and the report validator. They use
only stdlib, so they run on any platform (unlike test_tools.py, which needs
Windows system DLLs).
"""
import unittest

from dll_analyzer import explain, report
from dll_analyzer.evidence import EvidenceLog
from dll_analyzer.report import INFERRED, OBSERVED, UNKNOWN, Statement


class NameCheckTests(unittest.TestCase):
    def test_accepts_api_present_in_asm(self):
        answer = {"summary": "calls CreateFileW to open a file",
                  "detail": "", "instructions": []}
        allowed = "call CreateFileW\nmov rcx, rdx"
        ok, offenders = explain.verify_names(answer, allowed)
        self.assertTrue(ok)
        self.assertEqual(offenders, [])

    def test_flags_invented_api(self):
        answer = {"summary": "calls WinHttpConnect to reach the network",
                  "detail": "", "instructions": []}
        allowed = "call CreateFileW\nmov rcx, rdx"  # no WinHttpConnect here
        ok, offenders = explain.verify_names(answer, allowed)
        self.assertFalse(ok)
        self.assertIn("WinHttpConnect", offenders)

    def test_plain_english_is_not_flagged(self):
        answer = {"summary": "adds the two values and returns the result",
                  "detail": "the loop iterates over the array", "instructions": []}
        ok, offenders = explain.verify_names(answer, "add eax, ebx")
        self.assertTrue(ok, offenders)


class EvidenceLogTests(unittest.TestCase):
    def test_ids_increment_and_support_check(self):
        log = EvidenceLog(sha256="abc")
        e1 = log.record("list_imports", {"path": "x"},
                        [{"function": "RegSetValueExW", "dll": "advapi32.dll"}])
        self.assertEqual(e1, "E1")
        self.assertTrue(log.exists("E1"))
        self.assertFalse(log.exists("E9"))
        self.assertTrue(log.supports("E1", "RegSetValueExW"))
        self.assertFalse(log.supports("E1", "WinHttpOpen"))


class ReportValidatorTests(unittest.TestCase):
    def test_unsupported_observed_is_downgraded(self):
        log = EvidenceLog()
        eid = log.record("list_imports", {}, [{"function": "RegSetValueExW"}])
        stmts = [
            Statement(OBSERVED, "imports RegSetValueExW", [eid]),       # backed up
            Statement(OBSERVED, "imports WinHttpSendRequest", [eid]),   # not in evidence
            Statement(UNKNOWN, "which server it contacts", []),
        ]
        out = report.validate(stmts, log)
        self.assertEqual(out[0].label, OBSERVED)
        self.assertEqual(out[1].label, INFERRED)  # downgraded
        self.assertEqual(out[2].label, UNKNOWN)

    def test_dangling_citation_is_dropped(self):
        log = EvidenceLog()
        out = report.validate([Statement(INFERRED, "likely a parser", ["E99"])], log)
        self.assertEqual(out[0].evidence, [])


if __name__ == "__main__":
    unittest.main()
