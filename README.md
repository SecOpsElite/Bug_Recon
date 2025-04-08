# 🔍 Bug Recon

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0-brightgreen.svg)]()
[![Bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg)]()

<p align="center">
  <img src="/api/placeholder/800/400" alt="Bug Recon Banner">
</p>

## 🚀 Advanced GitHub Reconnaissance Tool for Bug Bounty Hunters

**Bug Recon** is a powerful, modular reconnaissance framework designed for bug bounty hunters and security researchers. It automates the entire GitHub reconnaissance process, helping you discover vulnerabilities faster and more efficiently.

> *"Finding bugs is an art—but first, you need the right canvas."*

## ⚡ Features

- **🔎 Intelligent GitHub Dorking** - Automatically searches for secrets, API keys, and sensitive information
- **📂 Smart Repository Analysis** - Clones and analyzes repositories with configurable depth
- **🔑 Multi-Engine Secrets Detection** - Powered by Gitleaks and TruffleHog
- **🔗 JavaScript Endpoint Extraction** - Discovers hidden API endpoints in JS files
- **🌐 Subdomain Discovery** - Extracts subdomains from code and validates with Subfinder
- **🔄 Live Host Probing** - Uses httpx to identify live services
- **📊 URL Discovery** - Leverages gau to find known URLs
- **📸 Web Application Screenshots** - Captures visual evidence with gowitness
- **🔒 Vulnerability Scanning** - Integrated with Nuclei for automated vuln detection
- **📈 Comprehensive Reporting** - Creates detailed markdown reports for your findings

## 🔧 Installation

### Prerequisites

The tool leverages powerful open-source security tools. Install these dependencies first:

```bash
# Core requirements
sudo apt-get install git
sudo apt-get install jq

# Install GitHub CLI and authenticate
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh
gh auth login

# Optional but recommended tools
# Secrets scanning
go install github.com/zricethezav/gitleaks/v8@latest
pip install trufflehog

# Subdomain and endpoint discovery
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# Visual reconnaissance
go install github.com/sensepost/gowitness@latest

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### Install Bug Recon

```bash
git clone https://github.com/yourcoolname/bug-recon.git
cd bug-recon
chmod +x Bug_Recon.sh
```

## 🚀 Usage

### Basic Usage

```bash
./Bug_Recon.sh -t TargetOrg -d target.com
```

### Advanced Options

```bash
./Bug_Recon.sh -t TargetOrg -d target.com -d dev.target.com -o ./my-recon --full-clone
```

### Full Command Reference

```
Usage: Bug_Recon.sh -t <target> [-o <out_dir>] [-d <domain>] [--full-clone] [--cleanup] [skip_flags...]

Required:
  -t, --target <username/org>  GitHub username or organization to scan.

Options:
  -o, --output <dir>           Output directory (default: ./github-recon-<target>).
  -d, --domain <domain>        Target domain for focused subdomain enumeration (can be used multiple times).
      --full-clone             Perform full git clones (default: shallow --depth=1).
      --cleanup                Remove cloned 'repos/' directory after script completion.
      --skip-dorking           Skip GitHub code search dorking.
      --skip-cloning           Skip cloning repositories (also skips local analysis steps).
      --skip-secrets           Skip Gitleaks and TruffleHog scans.
      --skip-endpoints         Skip JS endpoint extraction.
      --skip-subdomains-code   Skip subdomain extraction from code.
      --skip-subfinder         Skip subdomain enumeration using Subfinder.
      --skip-httpx             Skip live host probing using httpx.
      --skip-gau               Skip URL discovery using gau.
      --skip-gowitness         Skip screenshotting using gowitness.
      --skip-nuclei            Skip vulnerability scanning using Nuclei.
  -h, --help                   Show this help message.
  -v, --version                Show script version.
```

## 🔍 Workflow

Bug Recon follows a methodical approach to GitHub reconnaissance:

1. **GitHub Dorking** - Searches for sensitive info like API keys and secrets
2. **Repository Cloning** - Clones all public repositories of the target
3. **Secrets Scanning** - Runs Gitleaks and TruffleHog to detect secrets
4. **Endpoint Extraction** - Discovers API endpoints in JavaScript files
5. **Subdomain Extraction** - Extracts potential subdomains from code
6. **Subfinder Enumeration** - Discovers subdomains using Subfinder
7. **Live Host Probing** - Identifies live hosts with httpx
8. **URL Discovery** - Finds known URLs with gau
9. **Web Screenshots** - Captures screenshots with gowitness
10. **Vulnerability Scanning** - Runs Nuclei against discovered hosts

## 📊 Output

The tool generates a comprehensive directory structure with all findings:

```
github-recon-<target>/
├── dorking/
│   └── code-search-results.md
├── endpoints/
│   ├── js_endpoints_sorted.txt
│   └── urls_from_gau.txt
├── gowitness-results/
│   └── screenshots/
├── httpx-results/
│   └── live_hosts_httpx.txt
├── nuclei-results/
│   └── nuclei_scan_report.txt
├── repos/
│   ├── repo1/
│   ├── repo2/
│   └── ...
├── secrets/
│   ├── gitleaks/
│   └── trufflehog/
├── subdomains/
│   ├── subdomains_combined_unique.txt
│   ├── subdomains_from_code.txt
│   └── subdomains_from_subfinder.txt
├── recon-run-YYYYMMDD-HHMMSS.log
└── summary-report.md
```

## 📝 Example Report

The tool generates a Markdown summary report with detailed findings:

```markdown
# GitHub Reconnaissance Summary Report for TargetOrg
**Generated:** Tue Apr 8 14:30:45 EDT 2025
**Output Directory:** `/path/to/github-recon-TargetOrg`

## Execution Summary
- [GitHub Dorking](#github-dorking): Found potential items in 37 results
- [Repository Cloning](#repository-cloning): Cloned 12 repositories
- [Secrets Scanning](#secrets-scanning):
  - Gitleaks: Found 5 potential secrets
  - TruffleHog: Found 8 potential secrets
- [JS Endpoint Extraction](#js-endpoint-extraction): Found 143 potential endpoints
- [Subdomain Extraction (Code)](#subdomain-extraction-code): Found 26 potential domains
- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Found 52 subdomains
- [Live Host Probing (httpx)](#live-host-probing-httpx): Found 41 live hosts
- [URL Discovery (gau)](#url-discovery-gau): Found 876 URLs
- [Screenshotting (gowitness)](#screenshotting-gowitness): Completed
- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Found 13 potential findings

## Final Summary
**Total Execution Time:** 00 hours 12 minutes 47 seconds
```

## ⚠️ Responsible Usage

This tool is designed for security professionals with proper authorization. Always:

1. Only scan targets you have permission to test
2. Follow responsible disclosure practices
3. Respect rate limits and don't overload services
4. Report findings responsibly to the affected organization

## 🔒 Ethics

Bug Recon was created to help security researchers protect organizations by finding vulnerabilities before malicious actors do. We strongly encourage:

- Obtaining proper authorization before scanning
- Respecting published security policies
- Practicing responsible disclosure
- Following local laws and regulations

## 👨‍💻 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- The amazing open-source security community
- All the brilliant tools this script builds upon
- Bug bounty platforms that enable security research

## 🥇 CREDITS & LOVE ✨

Created with passion by **SecOpsElite** — Cybersecurity Specialist

Follow and support:

- 🥇 [Facebook](https://www.facebook.com/secopselite)
- 🥇 [Twitter (X)](https://x.com/secopselite)
- 🥇 [Pinterest](https://www.pinterest.com/secopselite/)
- 🥇 [Instagram](https://www.instagram.com/secopselite/)

---

> "Hunt bugs. Break systems. Report responsibly."

<p align="center">
  <img src="https://media.tenor.com/JynFuzUqj6EAAAAd/anonymous-dark.gif" width="350">
</p>
