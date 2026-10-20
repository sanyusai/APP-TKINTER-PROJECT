"""
Unit tests for the scanning engine and the PDF report (no GUI needed).

Run from the project folder:   python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import history, scanner                      # noqa: E402
from make_test_files import fake_pe_header             # noqa: E402


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, name, data):
        path = self.dir / name
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def analyse(self, name, data, threshold=100):
        return scanner.analyze_file(self.make(name, data), self.dir, threshold)

    def points(self, result, check_number):
        return next(c["points"] for c in result["checks"] if c["number"] == check_number)

    # --- individual checks -------------------------------------------------
    def test_plain_text_is_low_risk(self):
        r = self.analyse("notes.txt", "hello world\n" * 50)
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["level"], "Low concern")

    def test_extension_check(self):
        self.assertEqual(self.points(self.analyse("run.bat", "echo hi"), 1), scanner.POINTS["extension"])
        self.assertEqual(self.points(self.analyse("a.txt", "x"), 1), 0)

    def test_autorun_inf(self):
        self.assertGreater(self.points(self.analyse("autorun.inf", "[autorun]"), 1), 0)

    def test_double_extension(self):
        self.assertEqual(self.points(self.analyse("invoice.pdf.exe", fake_pe_header()), 2), scanner.POINTS["double_extension"])
        self.assertEqual(self.points(self.analyse("sample.exe.txt", "text"), 2), 0)     # last extension is harmless
        self.assertEqual(self.points(self.analyse("archive.tar.gz", b"\x1f\x8b" + bytes(300)), 2), 0)

    def test_signature_mismatch(self):
        r = self.analyse("picture.png", fake_pe_header())                                # executable disguised as PNG
        self.assertEqual(self.points(r, 3), scanner.POINTS["signature"])
        self.assertEqual(self.points(self.analyse("ok.pdf", "%PDF-1.4\n%%EOF"), 3), 0)
        self.assertEqual(self.points(self.analyse("fake.pdf", "just text, not a pdf"), 3), scanner.POINTS["signature"])

    def test_valid_pe_passes(self):
        r = self.analyse("tool.exe", fake_pe_header())
        self.assertEqual(self.points(r, 6), 0)
        self.assertIn("Valid PE structure", next(c for c in r["checks"] if c["number"] == 6)["evidence"])

    def test_broken_pe_flagged_and_not_double_counted(self):
        r = self.analyse("setup.exe", "plain text pretending to be a program\n" * 20)
        self.assertEqual(self.points(r, 6), scanner.POINTS["pe"])
        self.assertEqual(self.points(r, 3), 0)                                           # same problem, scored once
        self.assertEqual(r["score"], scanner.POINTS["extension"] + scanner.POINTS["pe"])

    def test_truncated_pe_header(self):
        data = bytearray(fake_pe_header())
        data[0x40:0x44] = b"XXXX"                                                         # corrupt the 'PE\0\0' signature
        self.assertEqual(self.points(self.analyse("bad.dll", bytes(data)), 6), scanner.POINTS["pe"])

    def test_entropy(self):
        self.assertEqual(scanner.shannon_entropy(b"\x00" * 1000), 0.0)
        self.assertAlmostEqual(scanner.shannon_entropy(bytes(range(256)) * 4), 8.0, places=3)
        self.assertEqual(self.points(self.analyse("random.bin", os.urandom(4096)), 5), scanner.POINTS["entropy"])
        self.assertEqual(self.points(self.analyse("clean.txt", "abc " * 500), 5), 0)

    def test_entropy_ignored_for_compressed_types(self):
        zipped = b"PK\x03\x04" + os.urandom(4096)
        self.assertEqual(self.points(self.analyse("bundle.zip", zipped), 5), 0)

    def test_size_checks(self):
        big = self.analyse("big.dat", bytes(2 * 1024 * 1024), threshold=1)
        self.assertEqual(self.points(big, 7), scanner.POINTS["size"])
        self.assertEqual(self.points(self.analyse("empty.ps1", b""), 7), scanner.POINTS["size"])
        self.assertEqual(self.points(self.analyse("empty.txt", b""), 7), 0)

    def test_sha256_matches_hashlib(self):
        import hashlib
        data = os.urandom(5000)
        r = self.analyse("blob.dat", data)
        self.assertEqual(r["sha256"], hashlib.sha256(data).hexdigest())

    def test_right_to_left_override(self):
        r = self.analyse("report‮fdp.exe", fake_pe_header())
        self.assertEqual(self.points(r, 2), scanner.POINTS["double_extension"])

    # --- scoring -----------------------------------------------------------
    def test_score_is_capped_and_levels(self):
        self.assertEqual(scanner.level_for_score(0), "Low concern")
        self.assertEqual(scanner.level_for_score(19), "Low concern")
        self.assertEqual(scanner.level_for_score(20), "Review recommended")
        self.assertEqual(scanner.level_for_score(50), "Elevated concern")
        self.assertEqual(scanner.level_for_score(75), "High concern")
        worst = self.analyse(".invoice.pdf.exe", os.urandom(2 * 1024 * 1024), threshold=1)
        self.assertLessEqual(worst["score"], 100)
        self.assertEqual(worst["level"], "High concern")

    def test_missing_file_is_reported_not_raised(self):
        r = scanner.analyze_file(self.dir / "nope.txt")
        self.assertEqual(r["level"], scanner.LEVEL_ERROR)
        self.assertTrue(r["error"])

    # --- listing + summary -------------------------------------------------
    def test_list_files_recursive_and_symlinks(self):
        self.make("a.txt", "a")
        (self.dir / "sub").mkdir()
        (self.dir / "sub" / "b.txt").write_text("b")
        (self.dir / "$RECYCLE.BIN").mkdir()
        (self.dir / "$RECYCLE.BIN" / "skip.txt").write_text("x")
        try:
            os.symlink(self.dir / "a.txt", self.dir / "link.txt")
        except (OSError, NotImplementedError):
            pass
        names = sorted(p.name for p in scanner.list_files(self.dir)[0])
        self.assertEqual(names, ["a.txt", "b.txt"])
        self.assertEqual([p.name for p in scanner.list_files(self.dir, recursive=False)[0]], ["a.txt"])

    def test_file_limit(self):
        for i in range(5):
            self.make(f"f{i}.txt", "x")
        files, truncated = scanner.list_files(self.dir, limit=3)
        self.assertEqual((len(files), truncated), (3, True))

    def test_summary(self):
        results = [self.analyse("a.txt", "hi"), self.analyse("b.exe", "text " * 40)]
        summary = scanner.summarise(results)
        self.assertEqual((summary["total"], summary["flagged"], summary["clean"]), (2, 1, 1))


class ReportTests(unittest.TestCase):
    def test_pdf_is_created(self):
        try:
            from core import report_pdf
        except ImportError:
            self.skipTest("reportlab not installed")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "invoice.pdf.exe").write_bytes(fake_pe_header())
            (root / "notes.txt").write_text("hi <b>& 日本語</b>")                      # special characters must not break the PDF
            (root / "weird‮.exe").write_bytes(b"MZ")
            files, _ = scanner.list_files(root)
            results = [scanner.analyze_file(p, root) for p in files]
            record = history.new_record(str(root), results, 100, True, "Completed", 0.1)
            out = report_pdf.generate_pdf(record, str(root / "report.pdf"))
            data = Path(out).read_bytes()
            self.assertTrue(data.startswith(b"%PDF"))
            self.assertGreater(len(data), 5000)

    def test_empty_scan_pdf(self):
        try:
            from core import report_pdf
        except ImportError:
            self.skipTest("reportlab not installed")
        with tempfile.TemporaryDirectory() as folder:
            record = history.new_record(folder, [], 100, True, "Completed", 0.0)
            report_pdf.generate_pdf(record, str(Path(folder) / "empty.pdf"))
            self.assertTrue((Path(folder) / "empty.pdf").exists())


if __name__ == "__main__":
    unittest.main()
