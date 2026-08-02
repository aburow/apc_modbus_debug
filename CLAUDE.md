# APC Modbus connectivity and device-profiling runbook

Use this runbook to diagnose an APC/Schneider Modbus TCP device and prepare
evidence for [apc-modbus-ha](https://github.com/aburow/apc-modbus-ha), the Home
Assistant integration. The required outcome is a completed JSON run from
`modbus-test.py` and an evidence-based device classification. It may be
`smt_ups`, `smart_ups`, `rack_pdu`, or `ambiguous`; never force a device type
to make a run appear successful.

Do not identify a device from its hostname, model label, SNMP data, or a
single successful register read. Preserve the schema-probe responses and
Modbus exceptions that caused the classification.

## Run

From this repository, first preserve the diagnostic template, then create the
working tool Claude will tune:

```bash
cp modbus-test.py modbus-working.py
python3 modbus-working.py --port 502 --unit 1 "<APC_HOST>" > apc-modbus-result.json
```

`modbus-test.py` remains the general diagnostic template. `modbus-working.py` is
the additional deliverable: a working, device-validated poller derived from
that template. Do not use `--human` for the diagnostic run: it omits the
per-probe evidence.
The script automatically tests the least restrictive working transport in this
order: one persistent session with no delay, one persistent session with a
three-second delay, then one request per connection with the same delays.
Let it finish; do not interrupt it during the three-second pacing checks.

## Completion and classification criteria

Inspect `apc-modbus-result.json`. A complete, useful run has:

- `modbus_pacing.ok` is `true`.
- `detection.decision` of `definitive`, or an explicitly reported `ambiguous`
  result with its probe evidence.
- All returned `modbus_probes`, `modbus`, `transport`, and `modbus_pacing`
  data retained for the handover.

The current classifier evidence is:

| Classification | Required evidence |
| --- | --- |
| `rack_pdu` | Rack-PDU capability and measurement probes both return the expected register counts and plausible capability values. |
| `smt_ups` | SMT measurement probe returns its expected registers, and legacy UPS ID returns exception `2` (`Illegal Data Address`). |
| `smart_ups` | Legacy UPS ID returns its expected registers, and SMT measurement probe returns exception `2`. |
| `ambiguous` | Any other mix of responses, short frames, exceptions, or transport failures. This is a valid diagnostic result, not a reason to guess. |

Record `transport.effective_mode` and
`transport.inter_request_delay_seconds`. These are operational settings for
the integration: reuse the selected mode and delay instead of assuming
persistent connections or immediate back-to-back requests work.

## If it does not succeed

Claude may alter timing and other variables in `modbus-working.py` to achieve a
complete diagnostic run. Keep `modbus-test.py` as the reusable baseline.
Change one variable at a time, run the full working poller after each change,
and save each resulting JSON file. Suitable changes include the Modbus timeout,
pacing delay, port, unit ID, and request/block parameters when supported by
the device evidence. Do not change the classifier merely to claim a device
type without supporting probe responses. Classify the blocker from the saved
JSON:

| Evidence | Blocker | Next action |
| --- | --- | --- |
| `modbus_pacing.ok: false` | No usable Modbus TCP path | Check the target IP/port, routing/VLAN/firewall rules, and that Modbus TCP is enabled on the UPS or network-management interface. |
| Pacing succeeds but a block has `error.code: read_failed` on a persistent session | Persistent connection is unreliable | Use one request per connection, or the reported delay, in the consuming program. |
| Pacing succeeds but `detected_device_type` is `ambiguous` | Insufficient or conflicting schema evidence | Preserve `modbus_probes` and raw block responses; verify the Modbus unit ID and firmware/interface configuration before extending the integration. |
| A probe returns `modbus_exception` other than the expected legacy exception `2` | Device accepted TCP but rejects that register/function | Treat the exception code as device/firmware evidence; do not retry aggressively. |

If a known non-default port or unit ID is supplied by the operator, repeat the
same complete command with `--port` and/or `--unit`. Do not scan ports or unit
IDs. If automatic pacing has found a working mode but the integration needs a
fixed delay, verify it with one final complete run, for example:

```bash
python3 modbus-working.py --port 502 --unit 1 --request-delay-seconds 3 "<APC_HOST>" > apc-modbus-result-delay-3.json
```

## Required report and handover

Return this concise report after every run, including a failed run:

```text
Plain-language summary: <what connected, whether the device was identified, what is preventing progress if anything, and the next action; avoid protocol jargon>
Target: <redacted host/IP>, port <port>, unit <unit>
Result: success | blocked
Detected device: <value from detection.detected_device_type>
Pacing: <effective_mode>, <inter_request_delay_seconds>s; attempts: <summary>
Evidence: <every schema probe response, exception code, or transport error>
Blocker: <none or exact failure category/message>
Working tool: <attached modbus-working.py filename and the command that completed>
Poller changes: <each modbus-working.py variable changed, old value, new value, result, and whether it should be retained>
Handover for apc-modbus-ha and other consumers:
- Transport: <persistent session or one request per connection>
- Minimum inter-request delay: <n>s
- Device rule: <the evidence-based rule used, or "ambiguous; do not support automatically">.
- Polling rule: <only registers demonstrated by this device; stop/reconnect behavior after a failed persistent read>.
- Preserve: <attached JSON filename and any raw_hex/probe errors>
- Follow-up: <network, UPS configuration, firmware, or parser action>
```

Write the plain-language summary first, in one short paragraph that a
non-specialist can act on. Attach the complete JSON result and `modbus-working.py`
to the handover. They are the source of truth for register support, exception
codes, pacing, raw Modbus frames, safe polling behavior, and validated tuning
to implement in apc-modbus-ha.
