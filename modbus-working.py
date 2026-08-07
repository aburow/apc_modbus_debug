#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0
"""Standalone, dependency-free APC Modbus TCP diagnostic poller."""

from __future__ import annotations

import argparse
import json
import math
import socket
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

MODBUS_TCP_PORT = 502
MODBUS_UNIT_ID = 1
MODBUS_TIMEOUT_SECONDS = 5
PACING_PROBE_SECONDS = 3
PACING_PROBE_ADDRESS = 0
PACING_PROBE_COUNT = 1
POST_PACING_DELAY_SECONDS = 2
MBAP_HEADER_LENGTH = 7
MODBUS_EXCEPTION_FLAG = 0x80

MODBUS_BLOCKS = [
    (0x0000, 23),
    (0x0080, 26),
    (0x0021, 10),
    (0x009E, 5),
    (0x00CF, 6),
    (0x023C, 21),
]
MODBUS_PROBES = [
    ("rack_pdu_capabilities", 0x009E, 5),
    ("rack_pdu_measurements", 0x00CF, 6),
    ("legacy_ups_id", 0x0021, 1),
    ("smt_status", 0x0000, 23),
    ("smt_measurements", 0x0080, 26),
]
MODBUS_EXCEPTION_NAMES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Slave Device Failure",
}


class ProbeKind(Enum):
    RESPONSE = "response"
    MODBUS_EXCEPTION = "modbus_exception"
    SHORT_RESPONSE = "short_response"
    TRANSPORT_FAILURE = "transport_failure"


@dataclass(frozen=True)
class ProbeOutcome:
    kind: ProbeKind
    registers: tuple[int, ...] = ()
    exception_code: int | None = None

    @property
    def unsupported(self) -> bool:
        return self.kind == ProbeKind.MODBUS_EXCEPTION and self.exception_code == 2


def read_holding_registers(
    connection: socket.socket, unit_id: int, address: int, count: int
) -> bytes:
    request = struct.pack(
        ">HHHBBHH", 1, 0, 6, unit_id, 3, address, count
    )
    connection.sendall(request)
    header = recv_exact(connection, MBAP_HEADER_LENGTH)
    _, _, length, _ = struct.unpack(">HHHB", header)
    payload = recv_exact(connection, length - 1)
    return header + payload


def recv_exact(connection: socket.socket, size: int) -> bytes:
    """Read exactly one Modbus TCP frame segment from a stream socket."""
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError(f"short Modbus response: expected {size} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_once(host: str, port: int, unit_id: int, address: int, count: int) -> bytes:
    with socket.create_connection((host, port), timeout=MODBUS_TIMEOUT_SECONDS) as conn:
        return read_holding_registers(conn, unit_id, address, count)


def parse_response(response: bytes) -> dict[str, Any]:
    if len(response) < 9:
        return {"error": {"code": "response_too_short"}}
    _, _, _, unit_id = struct.unpack(">HHHB", response[:MBAP_HEADER_LENGTH])
    function = response[MBAP_HEADER_LENGTH]
    if function & MODBUS_EXCEPTION_FLAG:
        code = response[MBAP_HEADER_LENGTH + 1]
        return {
            "error": {
                "code": "modbus_exception",
                "exception_code": code,
                "exception_name": MODBUS_EXCEPTION_NAMES.get(code, "Unknown"),
            }
        }
    byte_count = response[MBAP_HEADER_LENGTH + 1]
    data = response[9 : 9 + byte_count]
    return {
        "unit_id": unit_id,
        "registers": [
            struct.unpack(">H", data[index : index + 2])[0]
            for index in range(0, len(data), 2)
        ],
    }


def diagnose_pacing(
    host: str,
    port: int,
    unit_id: int,
    request_delay_seconds: float | None = None,
) -> dict[str, Any]:
    """Find the least restrictive connection mode that returns two replies."""
    attempts: list[dict[str, Any]] = []
    delays = (
        (request_delay_seconds,)
        if request_delay_seconds is not None
        else (0, PACING_PROBE_SECONDS)
    )
    for mode in ("session", "one_request_per_connection"):
        for delay in delays:
            try:
                if mode == "session":
                    with socket.create_connection(
                        (host, port), timeout=MODBUS_TIMEOUT_SECONDS
                    ) as conn:
                        read_holding_registers(conn, unit_id, PACING_PROBE_ADDRESS, PACING_PROBE_COUNT)
                        if delay:
                            time.sleep(delay)
                        read_holding_registers(conn, unit_id, PACING_PROBE_ADDRESS, PACING_PROBE_COUNT)
                else:
                    read_once(host, port, unit_id, PACING_PROBE_ADDRESS, PACING_PROBE_COUNT)
                    if delay:
                        time.sleep(delay)
                    read_once(host, port, unit_id, PACING_PROBE_ADDRESS, PACING_PROBE_COUNT)
            except (OSError, RuntimeError, struct.error) as err:
                attempts.append(
                    {
                        "mode": mode,
                        "request_delay_seconds": delay,
                        "ok": False,
                        "error": str(err),
                    }
                )
                continue
            attempts.append({"mode": mode, "request_delay_seconds": delay, "ok": True})
            return {
                "ok": True,
                "attempts": attempts,
                "effective_mode": mode,
                "inter_request_delay_seconds": delay,
            }
    return {"ok": False, "attempts": attempts}


def collect_block(
    host: str,
    port: int,
    unit_id: int,
    address: int,
    count: int,
    connection: socket.socket | None = None,
) -> dict[str, Any]:
    try:
        raw = (
            read_holding_registers(connection, unit_id, address, count)
            if connection else read_once(host, port, unit_id, address, count)
        )
    except (OSError, RuntimeError, struct.error) as err:
        return {"error": {"code": "read_failed", "message": str(err)}}
    return {"start": address, "count": count, "raw_hex": raw.hex(), "parsed": parse_response(raw)}


def probe_outcome(block: dict[str, Any] | None, count: int) -> ProbeOutcome:
    if not block or "parsed" not in block:
        return ProbeOutcome(ProbeKind.TRANSPORT_FAILURE)
    parsed = block["parsed"]
    registers = parsed.get("registers")
    if isinstance(registers, list):
        return (
            ProbeOutcome(ProbeKind.RESPONSE, tuple(registers))
            if len(registers) == count else ProbeOutcome(ProbeKind.SHORT_RESPONSE)
        )
    error = parsed.get("error", {})
    if error.get("code") == "modbus_exception":
        return ProbeOutcome(ProbeKind.MODBUS_EXCEPTION, exception_code=error.get("exception_code"))
    return ProbeOutcome(ProbeKind.SHORT_RESPONSE)


def detect_device(probes: dict[str, Any]) -> dict[str, Any]:
    outcomes = {name: probe_outcome(probes.get(name), count) for name, _, count in MODBUS_PROBES}
    capabilities = outcomes["rack_pdu_capabilities"]
    measurements = outcomes["rack_pdu_measurements"]
    legacy = outcomes["legacy_ups_id"]
    smt_status = outcomes["smt_status"]
    smt = outcomes["smt_measurements"]
    detected = None
    if capabilities.kind == measurements.kind == ProbeKind.RESPONSE:
        if len(capabilities.registers) == 5 and len(measurements.registers) == 6:
            phases, metered_phases, banks, outlets, metered_outlets = capabilities.registers
            if metered_phases <= phases and metered_outlets <= outlets and any((phases, banks, outlets)) and 0 <= measurements.registers[5] <= 4:
                detected = "rack_pdu"
    if smt.kind == ProbeKind.RESPONSE and legacy.unsupported:
        detected = "smt_ups"
    if legacy.kind == ProbeKind.RESPONSE and smt.unsupported:
        detected = "smart_ups"
    legacy_sentinel = (
        legacy.kind == ProbeKind.RESPONSE
        and len(legacy.registers) > 0
        and all(r == 0xFFFF for r in legacy.registers)
    )
    if (
        smt.kind == ProbeKind.RESPONSE and any(r != 0xFFFF for r in smt.registers)
        and smt_status.kind == ProbeKind.RESPONSE and any(r != 0 for r in smt_status.registers)
        and capabilities.unsupported
        and legacy_sentinel
    ):
        detected = "smartconnect_ups"
    return {
        "detected_device_type": detected,
        "decision": "definitive" if detected else "ambiguous",
        "probe_results": {name: outcome.kind.value for name, outcome in outcomes.items()},
    }


def collect(host: str, port: int, unit_id: int, request_delay_seconds: float | None) -> dict[str, Any]:
    if request_delay_seconds is not None and (
        request_delay_seconds < 0 or not math.isfinite(request_delay_seconds)
    ):
        raise ValueError("request_delay_seconds must be a finite non-negative number")
    result: dict[str, Any] = {
        "generated_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "host": "[redacted-ip]",
        "port": port,
        "unit_id": unit_id,
        "modbus": {},
        "modbus_probes": {},
    }
    pacing = diagnose_pacing(host, port, unit_id, request_delay_seconds)
    result["modbus_pacing"] = pacing
    if not pacing["ok"]:
        result["modbus_skipped_reason"] = "no_working_connection_pacing"
        result["detection"] = detect_device({})
        return result

    time.sleep(POST_PACING_DELAY_SECONDS)
    mode = pacing["effective_mode"]
    delay = request_delay_seconds if request_delay_seconds is not None else pacing["inter_request_delay_seconds"]
    result["transport"] = {
        "effective_mode": mode,
        "inter_request_delay_seconds": delay,
        "request_delay_source": "manual" if request_delay_seconds is not None else "diagnosed",
    }
    requests = [("modbus", f"0x{address:04X}_count_{count}", address, count) for address, count in MODBUS_BLOCKS]
    requests += [("probe", name, address, count) for name, address, count in MODBUS_PROBES]
    connection = None
    try:
        if mode == "session":
            connection = socket.create_connection((host, port), timeout=MODBUS_TIMEOUT_SECONDS)
        for index, (kind, key, address, count) in enumerate(requests):
            if index and delay:
                time.sleep(delay)
            block = collect_block(
                host, port, unit_id, address, count, connection
            )
            result["modbus" if kind == "modbus" else "modbus_probes"][key] = block
            if connection and "error" in block:
                result["modbus_skipped_reason"] = "persistent_connection_failed"
                break
    except OSError as err:
        result["modbus_skipped_reason"] = f"session_connection_failed: {err}"
    finally:
        if connection:
            connection.close()
    result["detection"] = detect_device(result["modbus_probes"])
    return result


def human_report(result: dict[str, Any]) -> str:
    pacing = result["modbus_pacing"]
    lines = ["APC Modbus diagnostics"]
    if not pacing["ok"]:
        return "\n".join(lines + ["Modbus pacing: no working connection mode found"])
    transport = result["transport"]
    lines.append(
        f"Modbus pacing: {transport['effective_mode']}, "
        f"{transport['inter_request_delay_seconds']}s between requests"
    )
    detection = result["detection"]
    lines.append(
        f"Device detection: {detection['detected_device_type'] or 'ambiguous'} "
        f"({detection['decision']})"
    )
    lines.append(f"Modbus blocks: {len(result['modbus'])} collected")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=MODBUS_TCP_PORT)
    parser.add_argument("--unit", type=int, default=MODBUS_UNIT_ID)
    parser.add_argument("--request-delay-seconds", type=float)
    parser.add_argument("--human", action="store_true")
    args = parser.parse_args()
    if args.request_delay_seconds is not None and (
        args.request_delay_seconds < 0
        or not math.isfinite(args.request_delay_seconds)
    ):
        parser.error("--request-delay-seconds must be a finite non-negative number")
    return args


def main() -> int:
    args = parse_args()
    result = collect(args.host, args.port, args.unit, args.request_delay_seconds)
    output = human_report(result) if args.human else json.dumps(result, indent=2)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
