from __future__ import annotations

import unittest

from scripts.phase5.common import percentile, redact, require_loopback
from scripts.phase5.native_bridge_probe import default_cases, http_request, parse_status, stale_phase5_runtime
from scripts.phase5.native_host_probe import decode_first_frame, encode_frame
from scripts.phase5.adversarial_load import status_from_response
from scripts.phase5.monitor_process import summarize
from scripts.phase5.report import aggregate
from scripts.phase5.evaluate_resources import evaluate
from scripts.phase5.validate_browser_evidence import REQUIRED_CASES, validate


class CommonTests(unittest.TestCase):
    def test_loopback_restriction(self) -> None:
        self.assertIn(require_loopback("localhost"), {"127.0.0.1", "::1"})
        with self.assertRaises(ValueError):
            require_loopback("192.0.2.1")

    def test_redaction(self) -> None:
        secret = "a" * 64
        self.assertNotIn(secret, redact(f"Authorization: Bearer {secret}"))

    def test_percentile(self) -> None:
        self.assertEqual(percentile([1.0, 2.0, 3.0], 0.5), 2.0)
        self.assertIsNone(percentile([], 0.95))


class BridgeProbeTests(unittest.TestCase):
    def test_matrix_has_unique_case_ids(self) -> None:
        ids = [case.case_id for case in default_cases()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 16)

    def test_unknown_protected_command_expects_authentication_first(self) -> None:
        unknown = next(case for case in default_cases() if case.case_id == "HTTP-15")
        self.assertEqual(unknown.expected_text, b"Unauthorized")

    def test_request_is_complete_and_scoped(self) -> None:
        request = http_request()
        self.assertIn(b"POST /api/handshake HTTP/1.1", request)
        self.assertIn(b"Content-Type: application/json", request)
        self.assertIn(b"X-PwdVault-Caller: chrome-extension://", request)
        self.assertIn(b'"protocol_version":1', request)

    def test_status_parser(self) -> None:
        self.assertEqual(parse_status(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"), 503)
        self.assertIsNone(parse_status(b"invalid"))

    def test_stale_runtime_detection(self) -> None:
        self.assertTrue(stale_phase5_runtime(b'{"error":"Unauthorized"}', False, False))
        self.assertFalse(stale_phase5_runtime(b'{"protocol_version":1,"success":true}', True, True))


class NativeHostProbeTests(unittest.TestCase):
    def test_frame_round_trip(self) -> None:
        payload = b'{"protocol_version":1}'
        self.assertEqual(decode_first_frame(encode_frame(payload)), payload)

    def test_truncated_frame_rejected(self) -> None:
        with self.assertRaises(ValueError):
            decode_first_frame(b"\x10\x00\x00\x00short")


class LoadAndMonitorTests(unittest.TestCase):
    def test_load_status_parser(self) -> None:
        self.assertEqual(status_from_response(b"HTTP/1.1 200 OK\r\n\r\n"), 200)

    def test_monitor_summary_fails_dead_process(self) -> None:
        result = summarize([{"alive": False}], 999999)
        self.assertEqual(result["status"], "FAIL")

    def test_report_propagates_blocked(self) -> None:
        result = aggregate([{"suite": "browser", "status": "BLOCKED"}], "release-macos")
        self.assertEqual(result["status"], "BLOCKED")

    def test_resource_thresholds_pass_bounded_deltas(self) -> None:
        baseline = {
            "summary": {
                "threads": {"last": 20},
                "rss_kib": {"last": 100_000},
                "open_files": {"last": 30},
            }
        }
        attack = {
            "samples": [{"alive": True}],
            "summary": {
                "threads": {"max": 28},
                "rss_kib": {"max": 150_000, "last": 110_000},
                "open_files": {"last": 35},
            },
        }
        self.assertEqual(evaluate(baseline, attack)["status"], "PASS")

    def test_complete_browser_evidence_passes(self) -> None:
        cases = {case: "PASS" for case in REQUIRED_CASES}
        evidence = {
            "platform": "macos",
            "windows": "DEFERRED",
            "browsers": {
                browser: {
                    "version": "test-version",
                    "artifact_sha256": "a" * 64,
                    "cases": cases,
                }
                for browser in ("chrome", "firefox")
            },
        }
        self.assertEqual(validate(evidence)["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
