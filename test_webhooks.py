import unittest
from webhooks import replay_request, sanitize, verify


class WebhookTests(unittest.TestCase):
    def test_verifies_hmac_signature(self):
        import hashlib, hmac
        signature = hmac.new(b"secret", b"payload", hashlib.sha256).hexdigest()
        self.assertTrue(verify("payload", signature, "secret"))
        self.assertFalse(verify("other", signature, "secret"))

    def test_sanitizes_nested_value(self):
        result = sanitize({"data": {"email": "a@example.com"}}, ["/data/email"])
        self.assertEqual(result["data"]["email"], "[REDACTED]")

    def test_builds_only_allowed_replay_target(self):
        request = replay_request({"id": "evt-1"}, "https://test.example/hook", {"test.example"})
        self.assertEqual(request["headers"]["Idempotency-Key"], "evt-1")
        with self.assertRaises(ValueError):
            replay_request({}, "https://other.example/hook", {"test.example"})


if __name__ == "__main__":
    unittest.main()
