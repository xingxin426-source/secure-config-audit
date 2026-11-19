# Secure Config Audit

A small, read-only Python tool for reviewing file permissions and recording SHA-256 baselines in a directory you own or are authorized to assess.

## What it checks

- Files writable by group or other users (POSIX systems).
- Optional SHA-256 inventory to help identify later file changes.
- Symlinks are reported but never followed; oversized files can be excluded.
- JSON report includes relative paths and findings only.

This is a learning/demo utility, not a substitute for an endpoint security product or a formal audit. It does not change files, contact remote systems, or attempt exploitation.

## Requirements

Python 3.10+; standard library only.

## Usage

```bash
python src/audit.py ./examples/sample-tree --json report.json
python src/audit.py ./examples/sample-tree --hash --json report.json
```

Exit codes: `0` no findings, `1` findings detected, `2` input or runtime error.

## Safe use

Only scan directories you own or have permission to review. Reports can reveal internal filenames; store and share them carefully. Test with the included synthetic example directory.

## Project status

Portfolio learning project. The findings are advisory and platform-dependent.

## License

MIT
