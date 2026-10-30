"""EWB Phishing URL Awareness Checker.

This program inspects URL text only. It never opens a URL or makes a network
request. Its findings are educational warning signs, not a safety verdict.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


NO_URL_MESSAGE = "No URL entered."
NO_HOST_MESSAGE = "Could not identify a hostname."
INVALID_URL_MESSAGE = "This text is not a valid URL format."
NO_WARNINGS_MESSAGE = (
    "No listed warning signs found. This does NOT prove safety."
)

# Messages that describe an input/result state rather than a detected warning.
INFO_MESSAGES = (
    NO_URL_MESSAGE,
    NO_HOST_MESSAGE,
    INVALID_URL_MESSAGE,
    "No listed warning signs found.",
)


def _is_ip_address(hostname: str) -> bool:
    """Return True when hostname is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def inspect_url(raw_url: str) -> list[str]:
    """Inspect URL text for the six warning signs in the project workbook.

    The function does not resolve a hostname, contact a server, or visit the
    supplied URL. It returns human-readable findings in a stable order.
    """
    if not isinstance(raw_url, str):
        return [INVALID_URL_MESSAGE]

    url = raw_url.strip()
    if not url:
        return [NO_URL_MESSAGE]

    # Unescaped whitespace/control characters are not valid in a URL as typed.
    if any(character.isspace() or ord(character) < 32 for character in url):
        return [INVALID_URL_MESSAGE]

    # Match the workbook's behaviour: a missing scheme is treated as HTTP.
    candidate = url if "://" in url else "http://" + url

    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        # For example, urlsplit raises ValueError for malformed bracketed IPv6.
        return [INVALID_URL_MESSAGE]

    if not host:
        return [NO_HOST_MESSAGE]

    findings: list[str] = []

    # 1. An @ symbol can make the apparent and actual hostname differ.
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully.")

    # 2. Long URLs can make the destination harder to inspect manually.
    if len(url) > 100:
        findings.append("Unusually long URL (over 100 characters).")

    # 3. A literal IP address is used instead of a domain name.
    # ipaddress validates the address rather than matching any four numbers.
    if _is_ip_address(host):
        findings.append("Uses an IP address instead of a familiar domain.")

    # 4. Five or more hostname labels means many hostname segments/subdomains.
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append("Contains many hostname segments/subdomains.")

    # 5. xn-- is the marker used by ASCII-compatible IDN/punycode labels.
    if "xn--" in host:
        findings.append("Contains a punycode-style hostname.")

    # 6. Plain HTTP does not provide transport encryption.
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP. HTTPS alone does not prove trust.")

    if not findings:
        findings.append(NO_WARNINGS_MESSAGE)

    return findings


def has_warnings(findings: list[str]) -> bool:
    """Distinguish detected warning signs from informational messages."""
    return any(not finding.startswith(INFO_MESSAGES) for finding in findings)


def main() -> None:
    """Run the interactive checker until the user enters a quit command."""
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")
    print("Type q, quit or exit when you are finished.")

    while True:
        try:
            raw_url = input("\nEnter a sample URL (or type q to quit): ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye! Stay alert online.")
            break

        if raw_url.strip().lower() in {"q", "quit", "exit"}:
            print("Goodbye! Stay alert online.")
            break

        findings = inspect_url(raw_url)

        print("\nResult:")
        for item in findings:
            print("- " + item)

        if has_warnings(findings):
            print(
                "\nREVIEW CAREFULLY: "
                f"{len(findings)} warning sign(s) found."
            )

        print("Never enter passwords from unexpected links.")


if __name__ == "__main__":
    main()
