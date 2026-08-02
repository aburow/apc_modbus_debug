# APC Modbus/SNMP Debug Collector

For a dependency-free Modbus-only report, use `modbus-test.py`:

```bash
python3 modbus-test.py --human <host>
```

`collector.py` is a standalone copy of the diagnostics collector used in
`../apc-modbus-ha/custom_components/apc_modbus/diagnostic_collector.py`.
This repository is intentionally standalone and versioned independently.

It probes:
- SNMP OIDs
- Modbus register blocks

`collector.py` uses the system `snmpget` and `snmpwalk` commands for SNMP.
`modbus-test.py` is dependency-free when only Modbus diagnostics are needed.

The goal is not to assume the device is healthy or fully standards-compliant. The goal is to capture a useful fingerprint of:
- what works
- what fails
- which OIDs exist
- which Modbus blocks respond
- which exception codes are returned
- any identity strings exposed by the device

## Usage

```bash
python3 collector.py --community public <host>
```

Example:

```bash
python3 collector.py --community public 192.168.1.10
```

To include a full SNMP walk of `1.3.6.1`, add `--full-snmp`:

```bash
python3 collector.py --full-snmp --community public 192.168.1.10
```

The collector determines the working Modbus connection mode and pacing before
it performs the full Modbus diagnostic sweep.

For a concise, human-readable report instead of the JSON diagnostic dump:

```bash
python3 collector.py --human --community public 192.168.1.10
```

To retain the detected connection mode but use a known request delay, add
`--request-delay-seconds 3`.

If SNMP is known to be unavailable, skip its probes with:

```bash
python3 collector.py --snmp-unavailable --human 192.168.1.10
```

Both scripts accept `--port` (default `502`) and `--unit` (default `1`).

## Claude-assisted device profiling

[`CLAUDE.md`](CLAUDE.md) is the runbook for diagnosing an APC/Schneider Modbus
TCP device and preparing a safe polling handover for
[apc-modbus-ha](https://github.com/aburow/apc-modbus-ha). It preserves
`modbus-test.py` as the generic diagnostic template and has Claude create
`modbus-working.py` as the tuned, device-validated tool.

Tell Claude the target address and any known non-default port or Modbus unit
ID. It also needs permission to connect to that device and edit files in this
repository. Use this prompt:

```text
Read CLAUDE.md and follow it completely. Diagnose the APC/Schneider Modbus TCP
device at <host or IP>. Use port <port, or 502> and Modbus unit ID <unit, or 1>.
Run modbus-working.py to completion, tune it only as documented, and return the
required plain-language report and technical handover. Attach the complete JSON
result and modbus-working.py for use in apc-modbus-ha.
```

Provide the port and unit ID only when known; do not ask Claude to scan for
them. A useful handover is possible even when detection is ambiguous or the
device is unreachable: it must include the exact blocker and saved JSON
evidence.

## Tests

Tests live in `test/` and run with pytest:

```bash
pytest -q test
```

## Output

The script emits JSON with:
- `snmp`: OID, value/error per probe
- `snmp_full`: optional full SNMP walk output from `1.3.6.1`
- `detection`: definitive device type only when Modbus schema probes agree
- `modbus_probes`: exact schema probe responses and protocol/transport outcome
- `modbus_pacing`: tested connection modes and the selected request delay
- `transport`: connection mode, effective delay, and whether it was manual or diagnosed
- `external_probe_tests`: detected external sensor OIDs and parsed values
- `modbus`: raw Modbus block responses, parsed registers, structured errors, and
  quick/identity decodes where available
- redaction applied to host/IP, community string, and serial-like fields

Errors are both human- and machine-readable. Example:

```json
{
  "error": {
    "code": "modbus_exception",
    "message": "Modbus exception 2: Illegal Data Address",
    "exception_code": 2,
    "exception_name": "Illegal Data Address"
  }
}
```

## Notes

- Probe failures are expected and useful.
- Unsupported SNMP OIDs and Modbus exception codes are part of the device fingerprint.
- Some APC devices return ASCII identity data in Modbus blocks that are numeric telemetry on other models.
- The raw dump is more trustworthy than any guessed high-level interpretation.

## Release

Current release: `v1.1.0`
