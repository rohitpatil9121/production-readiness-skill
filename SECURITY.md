# Security

This project is a set of instructions and read-only scanners. It doesn't run a
service or collect data. The scan scripts only read files in the repository you
point them at, and never print secret values.

If you find a way the scanner could leak a secret, execute code from the scanned
repo, or mislead Claude into a harmful action, please open a
[private security advisory](https://github.com/rohitpatil9121/production-readiness-skill/security/advisories/new)
rather than a public issue.

**About your reports:** an audit report is a map of exploitable bugs in your
project. Don't paste reports or scan output from private projects into public
issues; reduce them to a minimal example first.
