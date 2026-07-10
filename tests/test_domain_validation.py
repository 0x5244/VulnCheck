import unittest

import vulncheck

class DomainValidationTest(unittest.TestCase):
    def test_valid_domain(self):
        self.assertTrue(bool(vulncheck.is_valid_domain("example.com")))

    def test_invalid_domain(self):
        self.assertFalse(bool(vulncheck.is_valid_domain("bad_domain")))

if __name__ == "__main__":
    unittest.main()
