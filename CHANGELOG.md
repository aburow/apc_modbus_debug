# Changelog

All notable changes to this standalone debug collector are documented in this file.

## [1.2.0] - 2026-08-07

### Added
- Added `smartconnect_ups` device classification for the APC SmartConnect family.
  SmartConnect devices respond to SMT-era register blocks with live data but return
  the 0xFFFF "data not available" sentinel at legacy Smart-UPS addresses rather than
  raising Modbus Exception 2. The classifier requires: `smt_measurements` RESPONSE
  with at least one non-0xFFFF register, `smt_status` RESPONSE with at least one
  non-zero register, `rack_pdu_capabilities` Exception 2, and `legacy_ups_id`
  RESPONSE with all registers equal to 0xFFFF.
- Added `POST_PACING_DELAY_SECONDS = 2` and a corresponding post-pacing sleep to
  `modbus-test.py`, `modbus-working.py`, and `collector.py`. SmartConnect devices
  temporarily refuse new TCP connections immediately after a pacing session closes;
  the 2-second pause is benign for all other device types.

### Tests
- Added `test_smartconnect_ups_detection` to `test_collector.py` and
  `test_modbus_test.py`.

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
