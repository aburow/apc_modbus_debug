# Changelog

All notable changes to this standalone debug collector are documented in this file.

## Unreleased
### Changed
- Replaced the single idle probe with staged Modbus TCP idle checks at 5, 10,
  30, and 60 seconds.
- Added progress messages while the idle timer probe runs.
- Added explicit device-type reporting from SNMP and Modbus probes.
- Added external sensor OID detection and parsed external probe values to the
  report.
- Added an optional full SNMP walk dump via `--full-snmp`.

## [1.0.1] - 2026-04-05
### Changed
- Synced collector behavior with the Home Assistant diagnostics collector implementation.
- Added expanded SNMP probe set and Modbus diagnostic blocks.
- Added structured quick decode and identity decode output.
- Added recursive redaction for IP, community, and serial-like values.

### Tests
- Updated test suite for the new collector behavior and sanitization semantics.
- Verified with Ruff and Pytest.
