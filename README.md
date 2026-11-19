# Secure Config Audit

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-informational)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Learning%20Project-blue)

A lightweight, read-only Python utility for reviewing local file permissions and creating optional SHA-256 file inventories.

## Features

- Identifies files with group-write or other-write permission bits on POSIX systems.
- Optionally computes SHA-256 digests for regular files.
- Reports symbolic links without following them.
- Skips hashing files larger than a configurable size limit.
- Produces a JSON report for later review.

## Requirements

- Python 3.10 or newer
- Python standard library only

## Quick start

Clone the repository:

```bash
git clone https://github.com/xingxin426-source/secure-config-audit.git
cd secure-config-audit
```

Run a basic scan against the included synthetic sample:

```bash
python src/audit.py examples/sample-tree
```

Generate a JSON report and include SHA-256 digests:

```bash
python src/audit.py examples/sample-tree --hash --json report.json
```

Set a different maximum file size for hashing:

```bash
python src/audit.py examples/sample-tree --hash --max-bytes 5000000
```

## Example output

The command prints a short summary. When `--json` is supplied, the report contains:

- `generated_at`: UTC timestamp
- `root`: scanned directory
- `findings`: permission observations and unreadable-file notices
- `inventory`: discovered entries and optional hashes
- `hashes_skipped`: count of files excluded by the size limit

## Security and privacy notes

- Only scan directories you own or are explicitly authorized to assess.
- The tool is intended for local inventory and education; it does not remediate permissions.
- SHA-256 here is a file-integrity digest, **not** password hashing, authentication, or proof of file authenticity.
- Review generated reports before sharing them: paths and filenames may reveal private information.
- Hashing can encounter file changes between metadata inspection and file reading; do not treat this utility as a tamper-proof forensic collector.

## Project scope

This is a portfolio learning project, not a certified security scanner or a replacement for configuration-management, endpoint-security, or forensic tools. Findings are advisory and may vary by operating system and filesystem.

## License

MIT. See [LICENSE](LICENSE).
