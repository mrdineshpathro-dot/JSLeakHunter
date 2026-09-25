# 🔍 JSLeakHunter
### JavaScript Secret & Credential Scanner

A colorful, defensive, production-style CLI for finding accidentally exposed credentials in JavaScript, HTML, JSON, bundles, local web assets, and source maps. Built for Kali Linux, bug bounty workflows, DevSecOps, and authorized security reviews.

> **Safety first:** values are masked by default. JSLeakHunter performs passive GET requests only and never validates credentials by logging in or transmitting findings to third parties.

## Install (Kali Linux)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
# or: pipx install .
```

## Usage
```bash
jsleakhunter scan https://example.com
jsleakhunter scan --site https://example.com --depth 2 --threads 30
jsleakhunter scan --file app.js
jsleakhunter scan --dir ./dist/
cat urls.txt | jsleakhunter scan --stdin
jsleakhunter scan https://example.com --output report.html
jsleakhunter scan https://example.com --proxy http://127.0.0.1:8080 --insecure
jsleakhunter scan https://example.com --fail-on high --ci
```

## Features
- Data-driven detector plugins for cloud, Git, SaaS, databases, JWTs, private keys, bearer tokens, and contextual generic secrets.
- Entropy, placeholder filtering, confidence scoring, deduplication, fingerprints, line context, and safe masking.
- Async HTTP asset discovery with connection pooling, redirects, configurable concurrency, proxy and headers.
- JSON, CSV, Markdown, HTML reports; custom YAML signatures; CI exit codes; SQLite scan history.
- No arbitrary JavaScript execution and no automatic credential validation.

## Custom rules
```yaml
- name: Internal API Key
  regex: 'INTERNAL_[A-Z0-9]{32}'
  severity: high
  category: Internal
```
Use `--rules rules/example.yaml`. Test data in this repository is synthetic.

## Architecture
`scanner.py` orchestrates safe I/O; `detectors/` contains extensible signatures and layered scoring; `parsers/` handles asset discovery; `reporters/` provides output formats; `database/` stores local history.

## Development
```bash
pytest
python -m jsleakhunter doctor
```

## Author
**Mr Dinesh Pathro** · [Buy Me a Coffee](https://buymeacoffee.com/mrdineshpathro)

## License
MIT. Use only against systems you own or are explicitly authorized to assess.
