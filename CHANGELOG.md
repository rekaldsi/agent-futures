# Changelog

All notable changes to Agent Futures schemas will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `dispute.json` schema for structured dispute resolution
- `VERSIONING.md` with semver policy and backward compatibility rules
- `CHANGELOG.md` for tracking changes

---

## [0.2.0] - 2026-02-02

### Added
- Code validator with 16 security patterns (`/api/validate`)
- Permission manifest schema (`permission-manifest.json`)
- Permission inference API (`/api/permissions/infer`)
- Trust score computation API (`/api/trust/compute`)
- Trust score schema (`trust-score.json`)

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
| 0.2.0 | 2026-02-02 | Validator, permissions, trust scores |
| 0.1.0 | 2026-02-02 | Initial 4 schemas |

---

[Unreleased]: https://github.com/rekaldsi/agent-futures/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rekaldsi/agent-futures/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rekaldsi/agent-futures/releases/tag/v0.1.0
