# Changelog

## 0.2.0 (unreleased)

### Features

### Fixes

### Changes

## 0.1.0 (2026-04-19)

### Features

- Declarative DNS zone management with Rhai scripting
- AXFR zone transfer for fetching current zone state
- RFC 2136 dynamic updates with TSIG authentication
- Split-horizon DNS support (multiple views per zone)
- Record types: A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, SOA
- Multi-string TXT records via function overloads
- Externally managed records with `keep()` rules
- SOA comparison ignoring serial number
- Interactive confirmation, `--dry-run`, and `--no-confirm` modes
- TSIG key storage with optional argon2id + AES-256-GCM encryption
- Password caching across multiple encrypted keys
- TSIG key name override support
- Colored, column-aligned diff output
- Cross-platform support (Linux, macOS, Windows)
