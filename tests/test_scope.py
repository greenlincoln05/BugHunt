from datetime import datetime, timezone
import unittest

from bughunt.scope import check_scope


NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)


def policy(**overrides):
    value = {
        "id": "example",
        "name": "Example",
        "platform": "test",
        "program_url": "https://example.com/policy",
        "status": "active",
        "automation_allowed": True,
        "scope": ["https://example.com/api"],
        "excluded_scope": [],
        "verified_at": "2026-09-21T00:00:00Z",
        "verification_expires_at": "2026-09-22T00:00:00Z",
        "blocked_reason": None,
    }
    value.update(overrides)
    return value


class ScopeTests(unittest.TestCase):
    def allowed(self, url, **overrides):
        return check_scope(policy(**overrides), url, NOW)["allowed"]

    def test_origin_and_segment_boundaries(self):
        for url in ("https://example.com/api", "https://example.com/api/users", "https://example.com:443/api/"):
            with self.subTest(url=url):
                self.assertTrue(self.allowed(url))
        for url in ("https://example.com/apix", "https://evil.example.com/api", "https://example.com.evil/api", "http://example.com/api", "https://example.com:8443/api"):
            with self.subTest(url=url):
                self.assertFalse(self.allowed(url))

    def test_nondefault_port_and_scheme(self):
        scope = ["http://example.com:8080"]
        self.assertTrue(self.allowed("http://example.com:8080/any", scope=scope))
        self.assertFalse(self.allowed("http://example.com/any", scope=scope))
        self.assertFalse(self.allowed("https://example.com:8080/any", scope=scope))

    def test_hostname_and_wildcard_semantics(self):
        self.assertTrue(self.allowed("http://example.com:8080/path", scope=["example.com"]))
        self.assertFalse(self.allowed("https://sub.example.com/path", scope=["example.com"]))
        for host in ("a.example.com", "a.b.example.com"):
            self.assertTrue(self.allowed(f"https://{host}/", scope=["*.example.com"]))
        for host in ("example.com", "evilexample.com", "example.com.evil", "a.example.com.evil"):
            self.assertFalse(self.allowed(f"https://{host}/", scope=["*.example.com"]))

    def test_exclusions_always_win(self):
        self.assertFalse(self.allowed("https://example.com/api/admin", excluded_scope=["https://example.com/api/admin"]))
        self.assertTrue(self.allowed("https://example.com/api/administrators", excluded_scope=["https://example.com/api/admin"]))
        self.assertFalse(self.allowed("https://private.example.com/", scope=["*.example.com", "private.example.com"], excluded_scope=["private.example.com"]))

    def test_normalization(self):
        result = check_scope(policy(), "HTTPS://EXAMPLE.COM:443/%61pi/caf%C3%A9?q=%2f", NOW)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["normalized_url"], "https://example.com/api/caf%C3%A9?q=%2F")
        self.assertTrue(self.allowed("https://example.com/api", scope=["https://example.com/api/"]))
        result = check_scope(policy(scope=["https://bücher.example"]), "https://xn--bcher-kva.example/", NOW)
        self.assertTrue(result["allowed"])

    def test_exact_ips_ipv6_and_root_origin(self):
        self.assertTrue(self.allowed("https://192.0.2.1/any", scope=["192.0.2.1"]))
        self.assertFalse(self.allowed("https://192.0.2.2/any", scope=["192.0.2.1"]))
        self.assertTrue(self.allowed("http://[2001:0db8::1]:8080/a", scope=["http://[2001:db8::1]:8080"]))
        self.assertFalse(self.allowed("http://[2001:db8::2]:8080/a", scope=["http://[2001:db8::1]:8080"]))
        self.assertTrue(self.allowed("http://[::1]/", scope=["[::1]"]))
        self.assertFalse(self.allowed("http://192.0.2.1/", scope=["*.192.0.2.1"]))

    def test_ambiguous_target_urls_are_rejected(self):
        urls = [
            "https://example.com/api/../secret", "https://example.com/api/%2e%2e/secret",
            "https://example.com/api/%252e%252e/secret", "https://example.com/api/a%2fb",
            "https://example.com/api/a%5cb", "https://example.com/api/..;ignored/secret",
            "https://example.com/api//secret", "https://example.com/api/%00",
            "https://example.com/api/%0a", "https://example.com/api/%FF",
            "https://example.com/api/%xy", "https://example.com/api/%",
            "https://example.com\\evil/api", "https://example.com/api#fragment",
            "https://example.com/api#", "https://user@example.com/api",
            "https://example.com@evil.test/api", "https://example.com./api",
            " https://example.com/api", "https://exam\nple.com/api",
            "https://example.com:/api", "https://example.com:0/api",
            "https://example.com:65536/api", "https://example.com/api?q=%0d",
            "https://127.1/api", "https://2130706433/api", "https://0x7f000001/api",
            "https://0177.0.0.1/api", "https://[::1]evil/api",
            "file:///api", "//example.com/api", "https:///example.com/api",
        ]
        for url in urls:
            with self.subTest(url=url):
                result = check_scope(policy(), url, NOW)
                self.assertFalse(result["allowed"])
                self.assertIsNone(result["normalized_url"])

    def test_malformed_rules_fail_closed_even_if_another_rule_matches(self):
        invalid_rules = ["", "*", "example.com.evil/path", "https://example.com/api?q=1", "https://example.com/api#", "*.192.0.2.1", "example.com:443", None, 123]
        for rule in invalid_rules:
            with self.subTest(rule=rule):
                self.assertFalse(self.allowed("https://example.com/api", scope=["example.com", rule]))
                self.assertFalse(self.allowed("https://example.com/api", excluded_scope=[rule]))
        for field, value in (("scope", []), ("scope", "example.com"), ("excluded_scope", None), ("excluded_scope", "evil.test")):
            self.assertFalse(self.allowed("https://example.com/api", **{field: value}))

    def test_program_governance_denies_by_default(self):
        for changes in ({"status": "paused"}, {"status": "closed"}, {"status": None}, {"automation_allowed": False}, {"automation_allowed": "true"}, {"automation_allowed": 1}, {"blocked_reason": "Terms prohibit automated testing"}):
            with self.subTest(changes=changes):
                self.assertFalse(self.allowed("https://example.com/api", **changes))
        for field in ("status", "automation_allowed", "verified_at", "verification_expires_at", "scope", "excluded_scope"):
            value = policy()
            del value[field]
            self.assertFalse(check_scope(value, "https://example.com/api", NOW)["allowed"])

    def test_verification_window_and_malformed_timestamps(self):
        cases = [
            {"verified_at": None}, {"verified_at": "not-a-date"},
            {"verified_at": "2026-09-21T00:00:00"},
            {"verified_at": "2026-09-21T00:00:00-04:00"},
            {"verified_at": "2026-09-21T12:00:01Z"},
            {"verification_expires_at": "2026-09-21T12:00:00Z"},
            {"verification_expires_at": "2026-09-20T00:00:00Z"},
            {"verification_expires_at": "tomorrow"},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertFalse(self.allowed("https://example.com/api", **changes))
        self.assertTrue(self.allowed("https://example.com/api", verified_at="2026-09-21T12:00:00+00:00"))
        self.assertFalse(check_scope(policy(), "https://example.com/api", datetime(2026, 9, 21, 12))["allowed"])

    def test_result_contract_for_invalid_inputs(self):
        for target in (None, 10, ""):
            result = check_scope(policy(), target, NOW)
            self.assertEqual(set(result), {"allowed", "reason", "normalized_url"})
            self.assertFalse(result["allowed"])
            self.assertTrue(result["reason"])
        self.assertFalse(check_scope(None, "https://example.com/api", NOW)["allowed"])


if __name__ == "__main__":
    unittest.main()
