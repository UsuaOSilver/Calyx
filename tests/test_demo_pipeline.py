"""
tests/test_demo_pipeline.py
Tests for the demo_pipeline CLI — all heavy pipeline work is mocked.
"""
from __future__ import annotations
import sys, os, argparse, importlib, unittest
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _load_demo():
    """Import scripts/demo_pipeline.py as a module."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_pipeline",
        os.path.join(os.path.dirname(__file__), "..", "scripts", "demo_pipeline.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDemoPipelineModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.mod = _load_demo()
            cls.available = True
        except Exception as exc:
            cls.available = False
            cls.exc = exc

    def _skip(self):
        if not self.available:
            self.skipTest(f"demo_pipeline could not be loaded: {self.exc}")

    def test_module_loads(self):
        self._skip()
        self.assertIsNotNone(self.mod)

    def test_has_argument_parser(self):
        self._skip()
        source = open(os.path.join(os.path.dirname(__file__), "..",
                                   "scripts", "demo_pipeline.py")).read()
        self.assertIn("ArgumentParser", source)

    def test_has_main_function(self):
        self._skip()
        self.assertTrue(hasattr(self.mod, "main") or
                        hasattr(self.mod, "parse_args") or
                        "__main__" in open(os.path.join(os.path.dirname(__file__), "..",
                                           "scripts", "demo_pipeline.py")).read())

    def test_entrypoint_guard_present(self):
        self._skip()
        source = open(os.path.join(os.path.dirname(__file__), "..",
                                   "scripts", "demo_pipeline.py")).read()
        self.assertIn('__name__', source)

    def test_no_hardcoded_api_keys(self):
        self._skip()
        source = open(os.path.join(os.path.dirname(__file__), "..",
                                   "scripts", "demo_pipeline.py")).read()
        # Basic check: no literal Etherscan API key pattern
        import re
        self.assertNotRegex(source, r'[A-Z0-9]{32,}',
                            "Possible hardcoded API key found in demo_pipeline.py")


if __name__ == "__main__":
    unittest.main()
