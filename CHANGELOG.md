# Changelog

All notable changes to this standalone debug collector are documented in this file.

## [1.0.1] - 2026-04-05
### Changed
- Synced collector behavior with the Home Assistant diagnostics collector implementation.
- Added expanded SNMP probe set and Modbus diagnostic blocks.
- Added structured quick decode and identity decode output.
- Added recursive redaction for IP, community, and serial-like values.

### Tests
- Updated test suite for the new collector behavior and sanitization semantics.
- Verified with Ruff and Pytest.
