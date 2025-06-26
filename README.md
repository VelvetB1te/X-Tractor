# X-Tractor

**Author:** [Cyberveil](https://github.com/Cyberveil)  
**License:** GPLv3  
**Status:** In development

---

## Overview

**X-Tractor** is a Python tool that extracts Indicators of Compromise (IOCs) from `.pcap` files.  
It supports selective filtering, deduplication, and exports results in multiple formats.

---

## Features

- Parses PCAP traffic with `pyshark`
- Supports targeted extraction of:
  - IP addresses
  - DNS domains
  - SSL server names
  - FTP commands
  - SMTP addresses (including heuristics)
  - Ports and services
  - Raw data hashes (MD5, SHA1, SHA256)
  - URIs
- Outputs to CSV, JSON, Markdown, and HTML
- Deduplication modes (`--dedup`, `--dedup-ip`)
- CLI flags for quiet/verbose modes

---

## Installation

```bash
git clone https://github.com/Cyberveil/X-Tractor.git
cd X-Tractor
pip install -r requirements.txt
```

Python 3.9 or newer is recommended.

---

## Usage

Basic example:

```bash
python3 tractor.py path/to/file.pcap --all --json
```

Selective extraction:

```bash
python3 tractor.py path/to/file.pcap --ip --dns --uri --csv
```

With deduplication:

```bash
python3 tractor.py path/to/file.pcap --all --dedup --html
```

Quiet mode:

```bash
python3 tractor.py file.pcap --all --json --quiet
```

Verbose analysis:

```bash
python3 tractor.py file.pcap --smtp --verbose
```

---

## Output Formats

The tool can save reports in:
- `CSV` → `filename_report.csv`
- `JSON` → `filename_report.json`
- `Markdown` → `filename_report.md`
- `HTML` → `filename_report.html`

---

## Requirements

See `requirements.txt` for all dependencies.  
Core libraries:
- `pyshark`
- `requests`
- `pandas`

---

## Roadmap

- Performance improvements
- Advanced IOC enrichment
- GUI frontend
- Integration with threat platforms (MISP, OpenCTI)
- Plugin support

---

## License

This project is licensed under the GNU General Public License v3.0.  
See the [LICENSE](./LICENSE) file for full details.

---

## Contact

Developed by [Cyberveil](https://github.com/Cyberveil)  
For bug reports or feature requests, please open an issue on GitHub.
