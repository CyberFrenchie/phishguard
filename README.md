# PhishGuard

Simple, free, open-source CLI tool to quickly detect potential phishing in URLs or text snippets.

Built for threat intelligence workflows (inspired by Vankadel).

## Features
- Basic regex-based red flag detection (urgent language, crypto requests, HTTP, IP addresses, etc.)
- Typosquatting detection using Levenshtein distance (e.g. paypa1.com, g00gle.com)
- Text analysis for common phishing phrases

## Installation

```bash
pip install git+https://github.com/_CyberFrenchie/phishguard.git
