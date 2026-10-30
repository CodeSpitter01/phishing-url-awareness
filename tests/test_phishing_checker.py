"""Automated tests for the EWB Phishing URL Awareness Checker."""

import unittest
from unittest.mock import patch

from phishing_checker import (
    INVALID_URL_MESSAGE,
    NO_HOST_MESSAGE,
    NO_URL_MESSAGE,
    has_warnings,
    inspect_url,
    main,
)


class InspectUrlTests(unittest.TestCase):
    def test_workbook_sample_1_has_no_listed_warning_signs(self):
        self.assertEqual(
            inspect_url("https://www.example.com/login"),
            ["No listed warning signs found. This does NOT prove safety."],
        )

    def test_workbook_sample_2_flags_ip_and_http(self):
        self.assertEqual(
            inspect_url("http://192.0.2.10/account"),
            [
                "Uses an IP address instead of a familiar domain.",
                "Uses HTTP. HTTPS alone does not prove trust.",
            ],
        )

    def test_workbook_sample_3_flags_at_symbol_and_http(self):
        self.assertEqual(
            inspect_url("http://example.com@sample.invalid/login"),
            [
                "Contains an @ symbol; inspect carefully.",
                "Uses HTTP. HTTPS alone does not prove trust.",
            ],
        )

    def test_workbook_sample_4_flags_many_hostname_segments(self):
        self.assertEqual(
            inspect_url("https://a.b.c.d.e.example.invalid/path"),
            ["Contains many hostname segments/subdomains."],
        )

    def test_workbook_sample_5_flags_punycode(self):
        self.assertEqual(
            inspect_url("https://xn--example.invalid/"),
            ["Contains a punycode-style hostname."],
        )

    def test_empty_input_is_handled(self):
        self.assertEqual(inspect_url("   "), [NO_URL_MESSAGE])

    def test_missing_scheme_is_treated_as_http(self):
        self.assertIn(
            "Uses HTTP. HTTPS alone does not prove trust.",
            inspect_url("www.example.com"),
        )

    def test_url_over_100_characters_is_flagged(self):
        sample = "https://example.com/" + ("a" * 81)
        self.assertEqual(len(sample), 101)
        self.assertIn(
            "Unusually long URL (over 100 characters).",
            inspect_url(sample),
        )

    def test_url_of_exactly_100_characters_is_not_flagged_as_long(self):
        sample = "https://example.com/" + ("a" * 80)
        self.assertEqual(len(sample), 100)
        self.assertNotIn(
            "Unusually long URL (over 100 characters).",
            inspect_url(sample),
        )

    def test_invalid_ipv4_looking_hostname_is_not_accepted_as_an_ip(self):
        self.assertNotIn(
            "Uses an IP address instead of a familiar domain.",
            inspect_url("https://999.999.999.999/"),
        )

    def test_malformed_bracketed_ipv6_does_not_crash(self):
        self.assertEqual(inspect_url("http://[bad"), [INVALID_URL_MESSAGE])

    def test_whitespace_inside_url_is_rejected(self):
        self.assertEqual(
            inspect_url("https://example.com/a b"), [INVALID_URL_MESSAGE]
        )

    def test_ipv6_literal_is_detected_as_an_ip_hostname(self):
        self.assertIn(
            "Uses an IP address instead of a familiar domain.",
            inspect_url("https://[2001:db8::1]/"),
        )

    def test_hostless_url_is_handled(self):
        self.assertEqual(inspect_url("https://"), [NO_HOST_MESSAGE])

    def test_invalid_non_string_input_is_handled(self):
        self.assertEqual(inspect_url(None), [INVALID_URL_MESSAGE])

    def test_has_warnings_ignores_information_messages(self):
        self.assertFalse(
            has_warnings(["No listed warning signs found. This does NOT prove safety."])
        )
        self.assertFalse(has_warnings([NO_URL_MESSAGE]))

    def test_has_warnings_detects_warning_messages(self):
        self.assertTrue(
            has_warnings(["Uses HTTP. HTTPS alone does not prove trust."])
        )

    def test_main_repeats_until_quit(self):
        with patch("builtins.input", side_effect=["http://192.0.2.10/", "q"]):
            with patch("builtins.print") as mocked_print:
                main()
        printed_text = " ".join(str(call) for call in mocked_print.call_args_list)
        self.assertIn("REVIEW CAREFULLY", printed_text)
        self.assertIn("Goodbye! Stay alert online.", printed_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
