#!/usr/bin/env python3
from __future__ import annotations

import http.server
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


PROBE = Path(__file__).resolve().parents[1] / "cliproxyapi-fork-probe.py"


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path != "/v1/models" or self.headers.get("Authorization") != "Bearer test-key":
            self.send_error(403)
            return
        payload = json.dumps({"data": [{"id": "gpt-5.6-sol"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        if self.path != "/v1/responses" or request.get("model") != "gpt-5.6-sol":
            self.send_error(400)
            return
        if not request.get("stream"):
            payload = json.dumps({"output_text": "CPA_AUTO_UPDATE_OK"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        events = (
            'event: response.output_text.delta\n'
            'data: {"type":"response.output_text.delta","delta":"CPA_AUTO_"}\n\n'
            'event: response.output_text.delta\n'
            'data: {"type":"response.output_text.delta","delta":"UPDATE_OK"}\n\n'
            'event: response.completed\n'
            'data: {"type":"response.completed"}\n\n'
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(events)))
        self.end_headers()
        self.wfile.write(events)


class ProbeTests(unittest.TestCase):
    def test_all_mode_accepts_split_stream_marker_and_completion(self) -> None:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                config = Path(temp_dir) / "config.yaml"
                config.write_text(
                    f"port: {server.server_port}\napi-keys:\n  - test-key\n",
                    encoding="utf-8",
                )
                result = subprocess.run(
                    [str(PROBE), "all", "--config", str(config), "--attempts", "1"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "all")
        self.assertEqual(payload["probe_model"], "gpt-5.6-sol")
        self.assertNotIn("test-key", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
