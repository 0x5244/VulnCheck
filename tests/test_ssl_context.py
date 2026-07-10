import ssl
import unittest

from tests.ssl_tls import create_secure_ssl_context


class SecureSslContextTests(unittest.TestCase):
    def test_rejects_legacy_tls_versions(self):
        context = create_secure_ssl_context()

        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
