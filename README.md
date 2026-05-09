# PipGuard

A security tool to prevent accidental installation of malicious AI-generated packages.

## Problem

AI coding assistants (ChatGPT, Claude, Copilot) sometimes invent nonexistent Python packages. Developers might unknowingly run `pip install` on these hallucinated names, installing malware or typosquat packages that can compromise development environments.

## Solution

PipGuard intercepts package installations and provides real-time risk assessment:

- **Typosquatting detection** - Identifies packages mimicking popular libraries
- **Malicious package database** - Checks against known malicious packages from OSV, GitHub Advisory Database
- **Suspicious pattern detection** - Flags new packages with low download counts, obfuscated code
- **Warn-by-default approach** - Never blocks workflows, builds trust through informative warnings

## Installation

```bash
pip install pipguard
```

## Usage

```bash
# Install a package with safety check
pipguard install requests

# Scan requirements file
pipguard scan requirements.txt

# Audit current environment
pipguard audit .
```

## Risk Assessment

PipGuard analyzes packages for:

- **HIGH**: Known malicious packages or clear typosquats
- **MEDIUM**: Suspicious patterns (new package, low downloads, suspicious metadata)
- **LOW**: Minor concerns worth noting

Example warning:
```
⚠️  Suspicious package detected: "reqeusts"
Reasons:
- Similar to popular package "requests"
- Published 2 days ago
- Low download count
Risk score: HIGH

Continue anyway? (y/N)
```

## Data Sources

- [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)
- [PyPA Advisory Database](https://github.com/pypa/advisory-database)
- [OSV.dev](https://osv.dev/)
- [PyPI JSON API](https://pypi.org/pypi/json)

## License

MIT License - see [LICENSE](LICENSE) file for details.
