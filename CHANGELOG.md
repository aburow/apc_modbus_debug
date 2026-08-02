# Changelog

All notable changes to this standalone debug collector are documented in this file.

## [1.1.0] - 2026-08-03

### Changed
- Replaced staged Modbus TCP idle checks with automatic connection pacing
  detection and safe request-delay overrides.
- Added evidence-based device classification from Modbus schema probes.
- Added external sensor OID detection and parsed external probe values to the
  report.
- Added an optional full SNMP walk dump via `--full-snmp`.
- Added `modbus-test.py` for dependency-free Modbus-only diagnostics.
- Added Claude-assisted device-profiling and integration handover guidance.

### Tests
- Added pytest coverage for the collector and Modbus-only poller.

## [1.0.1] - 2026-04-05
### Changed
- Synced collector behavior with the Home Assistant diagnostics collector implementation.
- Added expanded SNMP probe set and Modbus diagnostic blocks.
- Added structured quick decode and identity decode output.
- Added recursive redaction for IP, community, and serial-like values.

### Tests
- Updated test suite for the new collector behavior and sanitization semantics.
- Verified with Ruff and Pytest.
