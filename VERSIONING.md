# Schema Versioning Policy

Agent Futures follows [Semantic Versioning 2.0.0](https://semver.org/) for all schemas.

## Version Format

```
MAJOR.MINOR.PATCH
```

**Current Version:** 0.2.0 (Alpha)

---

## Version Rules

### MAJOR (Breaking Changes)
Increment when you make incompatible schema changes:
- Removing required fields
- Changing field types
- Renaming fields
- Changing enum values in breaking ways
- Altering validation rules that reject previously valid data

**Example:** Changing `agentId` from string to object → `1.0.0` → `2.0.0`

### MINOR (Backward Compatible Additions)
Increment when you add functionality in a backward compatible manner:
- Adding new optional fields
- Adding new enum values (if consumers handle unknown gracefully)
- Adding new schemas to the spec
- Extending descriptions or examples

**Example:** Adding optional `metadata` field → `1.0.0` → `1.1.0`

### PATCH (Backward Compatible Fixes)
Increment when you make backward compatible bug fixes:
- Fixing typos in descriptions
- Clarifying documentation
- Fixing JSON Schema syntax errors
- Updating examples

**Example:** Fixing description typo → `1.0.0` → `1.0.1`

---

## Pre-1.0 (Current Phase)

While in `0.x.x`:
- Breaking changes MAY occur in MINOR versions
- The API is not yet stable
- Implementers should expect changes

**Stability commitment begins at `1.0.0`**

---

## Deprecation Policy

When deprecating fields or features:

1. **Announce** deprecation in release notes
2. **Mark** deprecated fields in schema with `"deprecated": true`
3. **Maintain** deprecated fields for at least 2 MINOR versions
4. **Remove** in next MAJOR version

---

## Schema Identification

Each schema includes version in its `$id`:

```json
{
  "$id": "https://agent-futures.onrender.com/schemas/v0.2/identity.json"
}
```

Older versions remain accessible at their versioned URLs.

---

## Changelog

All changes documented in [CHANGELOG.md](./CHANGELOG.md) with:
- Version number
- Release date
- Breaking changes (if any)
- New features
- Bug fixes
- Migration guide (for breaking changes)

---

## Backward Compatibility Commitment

From `1.0.0` onward:

| Change Type | Allowed in MINOR? | Allowed in PATCH? |
|-------------|-------------------|-------------------|
| Add optional field | ✅ Yes | ❌ No |
| Add required field | ❌ No | ❌ No |
| Remove field | ❌ No | ❌ No |
| Change field type | ❌ No | ❌ No |
| Extend enum | ✅ Yes* | ❌ No |
| Restrict enum | ❌ No | ❌ No |
| Loosen validation | ✅ Yes | ❌ No |
| Tighten validation | ❌ No | ❌ No |

*Consumers should handle unknown enum values gracefully

---

## Implementation Notes

Implementers SHOULD:
- Include schema version in API responses
- Support at least current and previous MINOR version
- Validate against specific schema version, not "latest"
- Handle unknown fields gracefully (ignore, don't reject)
