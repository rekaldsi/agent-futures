# Changelog

All notable changes to Agent Futures schemas will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [0.3.0] - 2026-02-03

### Added
- **Evidence spans** in validator findings (line numbers, character positions, code context)
- **Egress domain allowlist** check — pass `allowedEgress` to flag unknown outbound domains
- **Machine-readable report** with `schema_version`, structured rule IDs, evidence arrays
- `/api/validate/egress` endpoint to get default allowed domains
- Trust score **breakdown** showing component scores

### Changed
- Attestation weight in trust scores increased to 30% (up from 25%)
- Landing page updated: safer demo code, attestation focus highlighted
- Demo textarea no longer contains triggering exfil patterns
- Added `schema_version` field to validator output for automation

### Fixed
- External scanners no longer flag landing page as malicious (false positive)

---

## [0.2.0] - 2026-02-02

### Added
- Code validator with 16 security patterns (`/api/validate`)
- Permission manifest schema (`permission-manifest.json`)
- Permission inference API (`/api/permissions/infer`)
- Trust score computation API (`/api/trust/compute`)
- Trust score schema (`trust-score.json`)
- `dispute.json` schema for structured dispute resolution
- `VERSIONING.md` with semver policy and backward compatibility rules

### Changed
- Updated documentation with API examples

---

## [0.1.0] - 2026-02-02

### Added
- Initial schema release
- `identity.json` - Agent identity and key management
- `attestation.json` - Third-party attestations
- `escrow.json` - Payment escrow agreements
- `reputation.json` - Portable reputation scores
- Basic Express server with schema hosting
- Deployed to Render (https://agent-futures.onrender.com)

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.3.0 | 2026-02-03 | Evidence spans, egress allowlist, machine-readable output |
| 0.2.0 | 2026-02-02 | Validator, permissions, trust scores |
| 0.1.0 | 2026-02-02 | Initial 4 schemas |

---

[Unreleased]: https://github.com/rekaldsi/agent-futures/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/rekaldsi/agent-futures/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rekaldsi/agent-futures/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rekaldsi/agent-futures/releases/tag/v0.1.0
