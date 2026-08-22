import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "render_report.py"
SPEC = importlib.util.spec_from_file_location("render_report", SCRIPT)
render_report = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = render_report
SPEC.loader.exec_module(render_report)


def host_record(title="Panel"):
    return {
        "schema_version": "2",
        "meta": {
            "scan_id": "test-scan",
            "scan_started_at": "2026-08-22T00:00:00Z",
            "scan_mode": "connect",
            "port_spec": "443",
            "rate": 100,
            "tcp_retries": 1,
        },
        "ip": "192.0.2.10",
        "completed_at": "2026-08-22T00:00:01Z",
        "scan": {"open_ports": 1, "complete": True},
        "services": [
            {
                "port": 8443,
                "protocol": "https",
                "known_c2_port": True,
                "title": title,
                "server": "fixture",
                "classification": "admin_panel",
                "suspicion_score": 8,
                "suspicion_reasons": ["+2 admin keywords"],
                "fingerprints": [],
                "body_sha256": "a" * 64,
                "tls": {
                    "certificate_sha256": "b" * 64,
                    "subject": "CN=fixture",
                    "self_signed": True,
                },
            }
        ],
    }


class ReportRendererTests(unittest.TestCase):
    def test_renders_standalone_html_and_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scan.jsonl"
            source.write_text(json.dumps(host_record()) + "\n", encoding="utf-8")
            data = render_report.load_jsonl(source)
            html = render_report.render_html(data, "Fixture Report")
            markdown = render_report.render_markdown(data, "Fixture Report")

        self.assertIn("Fixture Report", html)
        self.assertIn("192.0.2.10", html)
        self.assertIn("Host / service explorer", html)
        self.assertIn("applyFilters", html)
        self.assertNotIn("https://cdn", html)
        self.assertIn("# Fixture Report", markdown)
        self.assertIn("https://192.0.2.10:8443/", markdown)

    def test_untrusted_values_are_html_escaped(self):
        dangerous = '</script><script>alert("x")</script>'
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scan.jsonl"
            source.write_text(json.dumps(host_record(dangerous)) + "\n", encoding="utf-8")
            rendered = render_report.render_html(render_report.load_jsonl(source), "Report")

        self.assertNotIn(dangerous, rendered)
        self.assertIn("&lt;/script&gt;", rendered)

    def test_rejects_an_invalid_json_line(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "broken.jsonl"
            source.write_text("{not json}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                render_report.load_jsonl(source)


if __name__ == "__main__":
    unittest.main()
