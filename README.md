# APC Modbus/SNMP Debug Collector

`collector.py` is a debugging and fingerprinting tool for APC devices.

It probes a small set of:
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

## Output

The script emits JSON with:
- `snmp`: raw SNMP responses for APC UPS and Rack PDU identity probes
- `modbus`: raw Modbus block responses, parsed registers, and structured errors

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
