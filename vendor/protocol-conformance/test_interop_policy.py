"""The hourly page must not turn public observations into outbound requests."""
import importlib.util
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("interop_under_test", HERE / "interop.py")
interop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(interop)


class InteropAdmissionTests(unittest.TestCase):
    def test_checkpoint_reader_refuses_private_network_before_connecting(self):
        # Exercise the real sibling loader from this unrelated test cwd too.
        with patch("socket.socket", side_effect=AssertionError("private socket was created")):
            with self.assertRaisesRegex(ValueError, "not public"):
                interop.get_text("http://127.0.0.1/checkpoint")

    def test_only_explicitly_trusted_active_peers_are_selected(self):
        doc = {
            "peers": [
                {"url": "https://seller.example/", "trusted": True, "status": "active"},
                {"url": "https://seller.example", "trusted": True, "status": "active"},
                {"url": "https://untrusted.example", "trusted": False, "status": "active"},
                {"url": "https://changed-key.example", "trusted": True, "status": "key_mismatch"},
                {"url": "https://string-true.example", "trusted": "true", "status": "active"},
                {"url": "https://missing-fields.example"},
            ],
            "pending": [
                {"url": "http://127.0.0.1:9001"},
                {"url": "http://169.254.169.254/latest/meta-data/"},
                {"url": "http://7f000001.01010101.rbndr.us"},
            ],
        }
        self.assertEqual(
            interop.admitted_peer_urls(doc, "https://reference.example"),
            ["https://reference.example", "https://seller.example"],
        )

    def test_page_generation_never_checks_a_pending_target(self):
        doc = {
            "peers": [{"url": "https://seller.example", "trusted": True, "status": "active"}],
            "pending": [{"url": "http://127.0.0.1:9001"}],
        }
        runner = types.SimpleNamespace(fetch=lambda url: (200, doc))
        checked = []

        def check(_runner, url):
            checked.append(url)
            return {"url": url, "kind": "provider", "passed": 1, "total": 1,
                    "allPassed": True, "draftNames": False, "checks": []}

        with tempfile.TemporaryDirectory() as directory:
            own = pathlib.Path(directory) / "own.txt"
            own.write_text("reference.example\n")
            with patch.object(interop, "_load_runner", return_value=runner), \
                    patch.object(interop, "check_peer", side_effect=check), \
                    patch.object(interop, "witness_lines", return_value=[]):
                self.assertEqual(interop.main(["--out", directory, "--own", str(own),
                                               "--hub", "https://reference.example"]), 0)
            self.assertEqual(checked, ["https://reference.example", "https://seller.example"])
            html = (pathlib.Path(directory) / "index.html").read_text()
            self.assertIn("1 quarantined observations were not probed", html)
            self.assertNotIn("127.0.0.1", html)


if __name__ == "__main__":
    unittest.main()
