# APC Modbus/SNMP Debug Collector

`collector.py` is a standalone copy of the diagnostics collector used in
`../apc-modbus-ha/custom_components/apc_modbus/diagnostic_collector.py`.
This repository is intentionally standalone and versioned independently.

It probes:
- SNMP OIDs
- Modbus register blocks

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

## Output

The script emits JSON with:
- `snmp`: OID, value/error per probe
- `snmp_full`: optional full SNMP walk output from `1.3.6.1`
- `detection`: likely device type from SNMP and Modbus probe results
- `external_probe_detection` and `external_probe_data`: detected external sensor
  OIDs and parsed values, if available
- `modbus`: raw Modbus block responses, parsed registers, structured errors, and
  quick/identity decodes where available
- `modbus_tcp_idle_probe`: staged Modbus TCP idle checks at 5, 10, 30, and 60
  seconds, with progress messages printed while the probe runs
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

Current release: `v1.0.1`
