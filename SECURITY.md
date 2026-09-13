# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in dns-security-auditor, please report it responsibly.

Use GitHub's private vulnerability reporting: on this repo's Security tab, click "Report a vulnerability." This opens a private advisory visible only to me, with no address needed.

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Acknowledgment within 48 hours
- Status update within 7 days
- Fix targeted within 30 days for confirmed vulnerabilities

**Scope:**
- The dns-security-auditor codebase
- The dns-audit.com web application
- DNS record parsing logic

**Out of scope:**
- Third-party services (Cloudflare, crt.sh)
- Social engineering attacks
- Denial of service attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| < 2.0   | No        |

## Responsible Disclosure

Please hold off on public disclosure until a fix is released. I credit reporters in the fix commit unless they would rather stay anonymous.
