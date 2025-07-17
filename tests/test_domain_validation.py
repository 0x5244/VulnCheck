import unittest
import importlib
import builtins
from types import ModuleType

class DomainValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orig_import = builtins.__import__

        def dummy_import(name, globals=None, locals=None, fromlist=(), level=0):
            try:
                return cls.orig_import(name, globals, locals, fromlist, level)
            except ModuleNotFoundError:
                mod = ModuleType(name)
                if fromlist:
                    for attr in fromlist:
                        setattr(mod, attr, ModuleType(f"{name}.{attr}"))
                return mod

        builtins.__import__ = dummy_import
        cls.vulncheck = importlib.import_module("vulncheck")
        builtins.__import__ = cls.orig_import

    def test_valid_domain(self):
        self.assertTrue(bool(self.vulncheck.is_valid_domain("example.com")))

    def test_invalid_domain(self):
        self.assertFalse(bool(self.vulncheck.is_valid_domain("bad_domain")))

if __name__ == "__main__":
    unittest.main()
