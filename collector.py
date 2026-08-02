# SPDX-License-Identifier: GPL-3.0
# Copyright (C) 2026 Anthony Burow
# https://github.com/aburow/apc-modbus-snmp-ha

"""On-demand diagnostics collector for APC devices (standalone CLI)."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, cast

MBAP_HEADER_LENGTH = 7
MIN_MODBUS_RESPONSE_LENGTH = 9
MODBUS_EXCEPTION_FLAG = 0x80
INT16_SIGN_BIT = 0x8000
INT16_MODULUS = 0x10000
ASCII_PRINTABLE_START = 32
ASCII_PRINTABLE_END = 126
MODBUS_TCP_PORT = 502
MODBUS_UNIT_ID = 1
SNMP_TIMEOUT_SECONDS = 10
MODBUS_TIMEOUT_SECONDS = 5
SNMP_FULL_WALK_ROOT = "1.3.6.1"
SNMP_FULL_WALK_TIMEOUT_SECONDS = 60
FREQUENCY_TENTHS_THRESHOLD = 400
IDLE_PROBE_ADDRESS = 0x0000
IDLE_PROBE_COUNT = 1
PACING_PROBE_SECONDS = 3
EXTERNAL_TEMP_1_OID_CANDIDATES = (
    "1.3.6.1.4.1.318.1.1.25.1.2.1.6.1.1",
    "1.3.6.1.4.1.318.1.1.25.1.2.1.6.1",
)
EXTERNAL_HUMIDITY_1_OID_CANDIDATES = (
    "1.3.6.1.4.1.318.1.1.25.1.2.1.7.1.1",
    "1.3.6.1.4.1.318.1.1.25.1.2.1.7.1",
)
EXTERNAL_TEMP_2_OID_CANDIDATES = (
    "1.3.6.1.4.1.318.1.1.25.1.2.1.6.2.1",
    "1.3.6.1.4.1.318.1.1.25.1.2.1.6.2",
)
EXTERNAL_HUMIDITY_2_OID_CANDIDATES = (
    "1.3.6.1.4.1.318.1.1.25.1.2.1.7.2.1",
    "1.3.6.1.4.1.318.1.1.25.1.2.1.7.2",
)
SNMP_INPUT_FREQUENCY_OID_CANDIDATES = (
    "1.3.6.1.4.1.318.1.1.1.3.2.4.0",
    "1.3.6.1.2.1.33.1.3.3.1.2.1",
)

MODBUS_EXCEPTION_NAMES: dict[int, str] = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Slave Device Failure",
    5: "Acknowledge",
    6: "Slave Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond",
}

SNMP_OIDS: dict[str, str] = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "apc_model_smartups": "1.3.6.1.4.1.318.1.1.1.1.1.1.0",
    "apc_model_rackpdu": "1.3.6.1.4.1.318.1.1.12.1.5.0",
    "apc_fw_smartups": "1.3.6.1.4.1.318.1.1.1.1.2.1.0",
    "apc_fw_rackpdu": "1.3.6.1.4.1.318.1.1.12.1.3.0",
    "apc_fw_date_smartups": "1.3.6.1.4.1.318.1.1.1.1.2.2.0",
    "apc_fw_date_rackpdu": "1.3.6.1.4.1.318.1.1.12.1.4.0",
    "apc_input_frequency": "1.3.6.1.4.1.318.1.1.1.3.2.4.0",
    "upsmib_input_frequency_line1": "1.3.6.1.2.1.33.1.3.3.1.2.1",
}

MODBUS_BLOCKS: list[tuple[int, int]] = [
    (0x0000, 0x0016 - 0x0000 + 1),
    (0x0080, 0x0099 - 0x0080 + 1),
    (0x0021, 0x002A - 0x0021 + 1),
    (0x009E, 0x00A2 - 0x009E + 1),
    (0x00CF, 0x00D4 - 0x00CF + 1),
    (0x023C, 0x0250 - 0x023C + 1),
]

MODBUS_PROBES: list[tuple[str, int, int]] = [
    ("rack_pdu_capabilities", 0x009E, 5),
    ("rack_pdu_measurements", 0x00CF, 6),
    ("legacy_ups_id", 0x0021, 1),
    ("smt_status", 0x0000, 23),
    ("smt_measurements", 0x0080, 26),
]

RUNTIME_BLOCK_KEY = "0x0080_count_26"
LEGACY_ID_BLOCK_KEY = "0x0021_count_10"
MODERN_ID_BLOCK_KEY = "0x023C_count_21"
REDACTED_IP = "[redacted-ip]"
REDACTED_COMMUNITY = "[redacted-community]"
REDACTED_SERIAL = "[redacted-serial]"
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SERIAL_FIELD_RE = re.compile(
    r"(?i)\b(sn|serial(?:\s+number)?)\s*[:=]\s*([A-Za-z0-9._/-]+)",
)
NUMERIC_VALUE_RE = re.compile(r"[-+]?\d+(?:\.\d+)?")


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


def _classify_device_type(probes: Mapping[str, ProbeOutcome]) -> str | None:
    capabilities = probes["rack_pdu_capabilities"]
    measurements = probes["rack_pdu_measurements"]
    legacy = probes["legacy_ups_id"]
    smt = probes["smt_measurements"]
    if (
        capabilities.kind == measurements.kind == ProbeKind.RESPONSE
        and len(capabilities.registers) == 5
        and len(measurements.registers) == 6
    ):
        phases, metered_phases, banks, outlets, metered_outlets = (
            capabilities.registers
        )
        if (
            metered_phases <= phases
            and metered_outlets <= outlets
            and any((phases, banks, outlets))
            and 0 <= measurements.registers[5] <= 4
        ):
            return "rack_pdu"
    if smt.kind == ProbeKind.RESPONSE and legacy.unsupported:
        return "smt_ups"
    if legacy.kind == ProbeKind.RESPONSE and smt.unsupported:
        return "smart_ups"
    return None


def _snmpget_value(host: str, community: str, oid: str) -> str | None:
    """Return SNMP value text for a single OID, or None on failure."""
    snmpget_path = shutil.which("snmpget")
    if snmpget_path is None:
        return None

    command = [snmpget_path, "-v", "2c", "-c", community, host, oid]
    completed = subprocess.run(  # noqa: S603
        command,
        capture_output=True,
        check=False,
        text=True,
        timeout=SNMP_TIMEOUT_SECONDS,
    )

    if completed.returncode != 0:
        return None

    stdout = completed.stdout.strip()
    if not stdout:
        return None

    _, _, value = stdout.partition("=")
    if not value:
        return stdout
    return value.strip()


def _snmpwalk_values(host: str, community: str, root_oid: str) -> dict[str, Any]:
    """Walk an SNMP subtree with net-snmp and return parsed OID/value entries."""
    snmpwalk_path = shutil.which("snmpwalk")
    if snmpwalk_path is None:
        return {
            "error": {
                "code": "snmpwalk_missing",
                "message": "snmpwalk command not found",
            }
        }

    command = [snmpwalk_path, "-v", "2c", "-c", community, "-On", host, root_oid]
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=SNMP_FULL_WALK_TIMEOUT_SECONDS,
        )
        timed_out = False
    except subprocess.TimeoutExpired as err:
        completed = err
        timed_out = True

    entries: list[dict[str, str]] = []
    stdout_text = completed.stdout if isinstance(completed.stdout, str) else ""
    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("No more variables left in this MIB View"):
            continue
        if " = " in line:
            oid_part, value_part = line.split(" = ", 1)
        else:
            oid_part, separator, value_part = line.partition("=")
            if not separator:
                continue
        oid = oid_part.strip()
        value = value_part.strip()
        if not oid:
            continue
        entries.append({"oid": oid, "value": value})

    result: dict[str, Any] = {
        "root_oid": root_oid,
        "entry_count": len(entries),
        "entries": entries,
    }
    if timed_out:
        result["timed_out"] = True
        result["error"] = {
            "code": "snmpwalk_timeout",
            "message": (
                f"snmpwalk timed out after {SNMP_FULL_WALK_TIMEOUT_SECONDS} seconds"
            ),
        }
    elif completed.returncode != 0:
        result["error"] = {
            "code": "snmpwalk_failed",
            "message": completed.stderr.strip() or "snmpwalk returned a non-zero exit status",
            "returncode": completed.returncode,
        }
    elif completed.stderr.strip():
        result["stderr"] = completed.stderr.strip()
    return result


def _parse_numeric_value(value: str | None) -> float | None:
    if value is None:
        return None
    matches = NUMERIC_VALUE_RE.findall(str(value))
    if not matches:
        return None
    try:
        return float(matches[-1])
    except (TypeError, ValueError):
        return None


def _parse_external_temp_c(value: str | None) -> float | None:
    raw = _parse_numeric_value(value)
    if raw is None or raw < 0:
        return None
    if raw > 120:
        return raw / 10.0
    return raw


def _parse_external_humidity_pct(value: str | None) -> float | None:
    raw = _parse_numeric_value(value)
    if raw is None or raw < 0:
        return None
    if raw > 100:
        return raw / 10.0
    return raw


def _parse_snmp_frequency_hz(value: str | None) -> float | None:
    raw = _parse_numeric_value(value)
    if raw is None or raw <= 0:
        return None
    return raw / 10.0 if raw > FREQUENCY_TENTHS_THRESHOLD else raw


def _decode_snmp_input_frequency(snmp_data: dict[str, Any]) -> dict[str, Any] | None:
    for source_key in ("apc_input_frequency", "upsmib_input_frequency_line1"):
        source = snmp_data.get(source_key)
        if not isinstance(source, dict):
            continue
        value = source.get("value")
        if not isinstance(value, str):
            continue
        parsed_hz = _parse_snmp_frequency_hz(value)
        if parsed_hz is not None:
            return {
                "input_frequency_hz": parsed_hz,
                "input_frequency_source": source_key,
            }
    return None


def _detect_external_probe_oids(
    host: str, community: str
) -> dict[str, str | None] | None:
    detection: dict[str, str | None] = {}
    candidate_groups = {
        "temp_1_oid": EXTERNAL_TEMP_1_OID_CANDIDATES,
        "humidity_1_oid": EXTERNAL_HUMIDITY_1_OID_CANDIDATES,
        "temp_2_oid": EXTERNAL_TEMP_2_OID_CANDIDATES,
        "humidity_2_oid": EXTERNAL_HUMIDITY_2_OID_CANDIDATES,
        "frequency_oid": SNMP_INPUT_FREQUENCY_OID_CANDIDATES,
    }

    for key, candidates in candidate_groups.items():
        selected_oid = None
        for oid in candidates:
            raw_value = _snmpget_value(host, community, oid)
            if raw_value is None:
                return None
            if key == "frequency_oid":
                parsed = _parse_snmp_frequency_hz(raw_value)
            elif key.startswith("temp"):
                parsed = _parse_external_temp_c(raw_value)
            else:
                parsed = _parse_external_humidity_pct(raw_value)
            if parsed is not None:
                selected_oid = oid
                break
        detection[key] = selected_oid
    return detection


def _collect_external_probe_data(
    host: str,
    community: str,
    detection: dict[str, str | None],
) -> dict[str, Any] | None:
    values: dict[str, Any] = {}
    for key, parser in (
        ("snmp_external_temp_1", _parse_external_temp_c),
        ("snmp_external_humidity_1", _parse_external_humidity_pct),
        ("snmp_external_temp_2", _parse_external_temp_c),
        ("snmp_external_humidity_2", _parse_external_humidity_pct),
        ("snmp_input_frequency", _parse_snmp_frequency_hz),
    ):
        oid_key = {
            "snmp_external_temp_1": "temp_1_oid",
            "snmp_external_humidity_1": "humidity_1_oid",
            "snmp_external_temp_2": "temp_2_oid",
            "snmp_external_humidity_2": "humidity_2_oid",
            "snmp_input_frequency": "frequency_oid",
        }[key]
        selected_oid = detection.get(oid_key)
        if not selected_oid:
            values[key] = None
            continue
        raw_value = _snmpget_value(host, community, selected_oid)
        if raw_value is None:
            return None
        values[key] = parser(raw_value)

    frequency_raw = None
    frequency_source_oid = None
    for candidate_oid in SNMP_INPUT_FREQUENCY_OID_CANDIDATES:
        raw_value = _snmpget_value(host, community, candidate_oid)
        if raw_value is None:
            return None
        if frequency_raw is None:
            frequency_raw = raw_value
            frequency_source_oid = candidate_oid
        if _parse_snmp_frequency_hz(raw_value) is not None:
            frequency_raw = raw_value
            frequency_source_oid = candidate_oid
            break

    values["snmp_input_frequency_raw"] = frequency_raw
    values["snmp_input_frequency_source_oid"] = frequency_source_oid
    return values


def _probe_outcome(modbus_block: dict[str, Any] | None, count: int) -> ProbeOutcome:
    """Turn diagnostic wire results into device classifier input."""
    if not modbus_block or "parsed" not in modbus_block:
        return ProbeOutcome(ProbeKind.TRANSPORT_FAILURE)
    parsed = modbus_block["parsed"]
    registers = parsed.get("registers")
    if isinstance(registers, list):
        return (
            ProbeOutcome(ProbeKind.RESPONSE, tuple(registers))
            if len(registers) == count
            else ProbeOutcome(ProbeKind.SHORT_RESPONSE)
        )
    error = parsed.get("error", {})
    if error.get("code") == "modbus_exception":
        return ProbeOutcome(
            ProbeKind.MODBUS_EXCEPTION, exception_code=error.get("exception_code")
        )
    return ProbeOutcome(ProbeKind.SHORT_RESPONSE)


def _build_detection_summary(modbus_probes: dict[str, Any]) -> dict[str, Any]:
    probes = {
        name: _probe_outcome(modbus_probes.get(name), count)
        for name, _, count in MODBUS_PROBES
    }
    detected = _classify_device_type(probes)
    return {
        "detected_device_type": detected,
        "probe_results": {
            name: {
                "category": outcome.kind.value,
                "registers": list(outcome.registers) if outcome.registers else None,
                "exception_code": outcome.exception_code,
            }
            for name, outcome in probes.items()
        },
        "decision": "definitive" if detected else "ambiguous",
    }


def _modbus_read_holding_registers(  # noqa: PLR0913
    host: str,
    port: int,
    unit_id: int,
    address: int,
    count: int,
    timeout: int = MODBUS_TIMEOUT_SECONDS,
) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as connection:
        return _modbus_read_holding_registers_on_connection(
            connection,
            unit_id,
            address,
            count,
        )


def _modbus_read_holding_registers_on_connection(
    connection: socket.socket,
    unit_id: int,
    address: int,
    count: int,
) -> bytes:
    transaction_id = 1
    protocol_id = 0
    request_length = 6
    function_code = 3
    mbap_header = struct.pack(
        ">HHHB",
        transaction_id,
        protocol_id,
        request_length,
        unit_id,
    )
    pdu = struct.pack(">BHH", function_code, address, count)
    payload_request = mbap_header + pdu

    connection.sendall(payload_request)
    header = _recv_exact(connection, MBAP_HEADER_LENGTH)

    _, _, response_length, _ = struct.unpack(">HHHB", header)
    payload = _recv_exact(connection, response_length - 1)

    return header + payload


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    """Read exactly one Modbus TCP frame segment from a stream socket."""
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError(f"Short Modbus response: expected {size} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _diagnose_modbus_pacing(
    host: str,
    port: int,
    unit_id: int,
    request_delay_seconds: float | None = None,
) -> dict[str, Any]:
    """Find the least restrictive connection pacing that returns two replies."""
    attempts: list[dict[str, Any]] = []

    def attempt(mode: str, delay_seconds: int) -> bool:
        try:
            if mode == "session":
                with socket.create_connection(
                    (host, port), timeout=MODBUS_TIMEOUT_SECONDS
                ) as connection:
                    _modbus_read_holding_registers_on_connection(
                        connection, unit_id, IDLE_PROBE_ADDRESS, IDLE_PROBE_COUNT
                    )
                    if delay_seconds:
                        time.sleep(delay_seconds)
                    _modbus_read_holding_registers_on_connection(
                        connection, unit_id, IDLE_PROBE_ADDRESS, IDLE_PROBE_COUNT
                    )
            else:
                _modbus_read_holding_registers(
                    host, port, unit_id, IDLE_PROBE_ADDRESS, IDLE_PROBE_COUNT
                )
                if delay_seconds:
                    time.sleep(delay_seconds)
                _modbus_read_holding_registers(
                    host, port, unit_id, IDLE_PROBE_ADDRESS, IDLE_PROBE_COUNT
                )
        except (OSError, RuntimeError, struct.error) as err:
            attempts.append(
                {
                    "mode": mode,
                    "request_delay_seconds": delay_seconds,
                    "ok": False,
                    "error": {
                        "code": "modbus_pacing_probe_failed",
                        "message": str(err),
                        "exception_type": type(err).__name__,
                    },
                }
            )
            return False
        attempts.append(
            {"mode": mode, "request_delay_seconds": delay_seconds, "ok": True}
        )
        return True

    delays = (
        (request_delay_seconds,)
        if request_delay_seconds is not None
        else (0, PACING_PROBE_SECONDS)
    )
    for mode in ("session", "one_request_per_connection"):
        for delay_seconds in delays:
            if attempt(mode, delay_seconds):
                return {
                    "ok": True,
                    "attempts": attempts,
                    "effective_mode": mode,
                    "inter_request_delay_seconds": delay_seconds,
                }
    return {"ok": False, "attempts": attempts}


def _parse_modbus_response(response: bytes) -> dict[str, Any]:
    if len(response) < MIN_MODBUS_RESPONSE_LENGTH:
        return {
            "error": {
                "code": "modbus_response_too_short",
                "message": "response too short",
            },
        }

    _, _, _, unit_id = struct.unpack(">HHHB", response[:MBAP_HEADER_LENGTH])
    function_code = response[MBAP_HEADER_LENGTH]
    if function_code & MODBUS_EXCEPTION_FLAG:
        exception_code = response[MBAP_HEADER_LENGTH + 1]
        exception_name = MODBUS_EXCEPTION_NAMES.get(
            exception_code,
            "Unknown Modbus Exception",
        )
        return {
            "error": {
                "code": "modbus_exception",
                "message": f"Modbus exception {exception_code}: {exception_name}",
                "exception_code": exception_code,
                "exception_name": exception_name,
            },
        }

    byte_count = response[MBAP_HEADER_LENGTH + 1]
    data = response[
        MIN_MODBUS_RESPONSE_LENGTH : MIN_MODBUS_RESPONSE_LENGTH + byte_count
    ]
    registers = [
        struct.unpack(">H", data[index : index + 2])[0]
        for index in range(0, len(data), 2)
    ]
    return {"unit_id": unit_id, "registers": registers}


def _decode_uint32(registers: list[int], index: int) -> int | None:
    if index + 1 >= len(registers):
        return None
    return (registers[index] << 16) | registers[index + 1]


def _decode_int16(value: int) -> int:
    return value - INT16_MODULUS if value >= INT16_SIGN_BIT else value


def _decode_ascii_registers(registers: list[int]) -> str:
    chars: list[str] = []
    for register in registers:
        code_point = register & 0xFF
        if not code_point:
            continue
        if ASCII_PRINTABLE_START <= code_point <= ASCII_PRINTABLE_END:
            chars.append(chr(code_point))
    return "".join(chars).strip()


def _block_index(address: int) -> int:
    return address - 0x0080


def _scaled_register(
    registers: list[int],
    address: int,
    divisor: int,
    *,
    signed: bool = False,
) -> float | None:
    index = _block_index(address)
    if len(registers) <= index:
        return None
    value = _decode_int16(registers[index]) if signed else registers[index]
    return value / divisor


def _build_quick_decode(registers: list[int]) -> dict[str, float | int | None]:
    return {
        "runtime_remaining": _decode_uint32(registers, _block_index(0x0080)),
        "soc_pct": _scaled_register(registers, 0x0082, 512),
        "batt_v_pos": _scaled_register(registers, 0x0083, 32, signed=True),
        "batt_v_neg": _scaled_register(registers, 0x0084, 32, signed=True),
        "batt_temp_c": _scaled_register(registers, 0x0087, 128, signed=True),
        "out_load_pct": _scaled_register(registers, 0x0088, 256),
        "out_current": _scaled_register(registers, 0x008C, 32),
        "out_voltage": _scaled_register(registers, 0x008E, 64),
        "out_freq": _scaled_register(registers, 0x0090, 128),
        "out_energy_wh": _decode_uint32(registers, _block_index(0x0091)),
        "in_voltage": _scaled_register(registers, 0x0097, 64),
    }


def _sanitize_text(value: str, host: str, community: str) -> str:
    """Redact sensitive strings in diagnostics output."""
    text = value
    if host:
        text = text.replace(host, REDACTED_IP)
    text = IPV4_RE.sub(REDACTED_IP, text)
    if community:
        text = text.replace(community, REDACTED_COMMUNITY)

    def _serial_replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}: {REDACTED_SERIAL}"

    return SERIAL_FIELD_RE.sub(_serial_replace, text)


def _sanitize_data(value: Any, host: str, community: str) -> Any:  # noqa: ANN401
    """Recursively sanitize sensitive values in diagnostics data."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        typed_dict = cast("dict[str, Any]", value)
        for key, item in typed_dict.items():
            if key == "oid" or key.endswith("_oid"):
                sanitized[key] = item
                continue
            sanitized[key] = _sanitize_data(item, host, community)
        return sanitized
    if isinstance(value, list):
        typed_list = cast("list[Any]", value)
        return [_sanitize_data(item, host, community) for item in typed_list]
    if isinstance(value, str):
        return _sanitize_text(value, host, community)
    return value


async def _collect_snmp_data(host: str, community: str) -> dict[str, Any]:
    """Collect targeted SNMP probes, stopping at the first failure."""
    result: dict[str, Any] = {}
    for key, oid in SNMP_OIDS.items():
        try:
            value = await asyncio.to_thread(_snmpget_value, host, community, oid)
        except Exception as err:  # noqa: BLE001
            result[key] = {
                "oid": oid,
                "error": {
                    "code": "snmp_exception",
                    "message": str(err),
                    "exception_type": type(err).__name__,
                },
            }
            break
        if value is None:
            result[key] = {
                "oid": oid,
                "error": {"code": "snmp_missing", "message": "No value returned"},
            }
            break
        result[key] = {"oid": oid, "value": value}
    return result


def _snmp_failed(snmp_data: dict[str, Any]) -> bool:
    return any(
        isinstance(value, dict) and "error" in value
        for value in snmp_data.values()
    )


def _collect_modbus_block(
    host: str,
    port: int,
    unit_id: int,
    start: int,
    count: int,
    connection: socket.socket | None = None,
) -> dict[str, Any]:
    try:
        raw = (
            _modbus_read_holding_registers_on_connection(
                connection, unit_id, start, count
            )
            if connection
            else _modbus_read_holding_registers(host, port, unit_id, start, count)
        )
        parsed = _parse_modbus_response(raw)
    except (OSError, RuntimeError, struct.error) as err:
        return {
            "error": {
                "code": "modbus_block_read_failed",
                "message": str(err),
                "exception_type": type(err).__name__,
            },
        }

    return {
        "start": start,
        "count": count,
        "raw_hex": raw.hex(),
        "parsed": parsed,
    }


def _add_decodes(dump: dict[str, Any]) -> None:
    snmp_decode = _decode_snmp_input_frequency(dump.get("snmp", {}))
    if snmp_decode:
        dump["snmp_decode"] = snmp_decode

    runtime_block = dump["modbus"].get(RUNTIME_BLOCK_KEY)
    if runtime_block and "parsed" in runtime_block:
        parsed = runtime_block["parsed"]
        registers = parsed.get("registers")
        if registers:
            runtime_block["quick_decode"] = _build_quick_decode(registers)

    legacy_block = dump["modbus"].get(LEGACY_ID_BLOCK_KEY)
    if legacy_block and "parsed" in legacy_block:
        registers = legacy_block["parsed"].get("registers")
        if registers:
            legacy_id = _decode_ascii_registers(registers[1:9])
            if legacy_id:
                legacy_block["identity_decode"] = {"legacy_ups_id": legacy_id}

    modern_block = dump["modbus"].get(MODERN_ID_BLOCK_KEY)
    if modern_block and "parsed" in modern_block:
        registers = modern_block["parsed"].get("registers")
        if registers:
            ascii_chunks = {
                f"0x{0x023C + index:04X}": decoded
                for index in range(0, len(registers), 8)
                if (decoded := _decode_ascii_registers(registers[index : index + 8]))
            }
            if ascii_chunks:
                modern_block["identity_decode"] = {"ascii_chunks": ascii_chunks}


def collect_diagnostic_dump(
    host: str,
    community: str,
    port: int,
    unit_id: int,
    *,
    full_snmp: bool = False,
    snmp_availability: str = "unknown",
    request_delay_seconds: float | None = None,
) -> dict[str, Any]:
    """Collect SNMP and Modbus diagnostic data for one APC device."""
    if request_delay_seconds is not None and (
        request_delay_seconds < 0 or not math.isfinite(request_delay_seconds)
    ):
        raise ValueError("request_delay_seconds must be a finite non-negative number")
    snmp_data = (
        asyncio.run(_collect_snmp_data(host, community))
        if snmp_availability != "unavailable"
        else {"skipped_reason": "snmp_unavailable"}
    )
    snmp_full: dict[str, Any] | None = None
    snmp_failed = _snmp_failed(snmp_data)
    if full_snmp and snmp_availability != "unavailable" and not snmp_failed:
        sys.stderr.write(
            f"Collecting full SNMP walk from {SNMP_FULL_WALK_ROOT}\n"
        )
        sys.stderr.flush()
        snmp_full = _snmpwalk_values(host, community, SNMP_FULL_WALK_ROOT)
        sys.stderr.write(
            f"Full SNMP walk complete with {snmp_full.get('entry_count', 0)} entries\n"
        )
        sys.stderr.flush()
    dump: dict[str, Any] = {
        "generated_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "host": REDACTED_IP,
        "port": port,
        "unit_id": unit_id,
        "snmp": snmp_data,
        "modbus": {},
        "modbus_probes": {},
        "snmp_availability": snmp_availability,
    }
    if snmp_full is not None:
        dump["snmp_full"] = snmp_full
    elif full_snmp and snmp_failed:
        dump["snmp_full"] = {"skipped_reason": "snmp_failure"}

    pacing = _diagnose_modbus_pacing(
        host, port, unit_id, request_delay_seconds
    )
    dump["modbus_pacing"] = pacing
    effective_delay_seconds = (
        request_delay_seconds
        if request_delay_seconds is not None
        else pacing.get("inter_request_delay_seconds")
    )
    dump["transport"] = {
        "effective_mode": pacing.get("effective_mode"),
        "inter_request_delay_seconds": effective_delay_seconds,
        "request_delay_source": (
            "manual" if request_delay_seconds is not None else "diagnosed"
        ),
    }

    requests = [
        ("modbus", f"0x{start:04X}_count_{count}", start, count)
        for start, count in MODBUS_BLOCKS
    ] + [("probe", name, start, count) for name, start, count in MODBUS_PROBES]
    if pacing["ok"]:
        delay_seconds = effective_delay_seconds
        connection = None
        if pacing["effective_mode"] == "session":
            try:
                connection = socket.create_connection(
                    (host, port), timeout=MODBUS_TIMEOUT_SECONDS
                )
            except OSError as err:
                dump["modbus_skipped_reason"] = "session_connection_failed"
                dump["modbus_pacing"]["diagnostic_error"] = str(err)
        if "modbus_skipped_reason" not in dump:
            try:
                for index, (kind, key, start, count) in enumerate(requests):
                    if index and delay_seconds:
                        time.sleep(delay_seconds)
                    block = _collect_modbus_block(
                        host, port, unit_id, start, count, connection
                    )
                    dump["modbus" if kind == "modbus" else "modbus_probes"][key] = block
                    if connection and "error" in block:
                        dump["modbus_skipped_reason"] = "persistent_connection_failed"
                        break
            finally:
                if connection:
                    connection.close()
    else:
        dump["modbus_skipped_reason"] = "no_working_connection_pacing"

    if snmp_availability == "unavailable" or snmp_failed:
        dump["external_probe_tests"] = {
            "skipped_reason": (
                "snmp_unavailable" if snmp_availability == "unavailable" else "snmp_failure"
            )
        }
    else:
        detection = _detect_external_probe_oids(host, community)
        if detection is None:
            dump["external_probe_tests"] = {
                "detect": {"ok": False, "error": {"code": "snmp_failure"}}
            }
        else:
            values = _collect_external_probe_data(host, community, detection)
            dump["external_probe_tests"] = (
                {
                    "detect": {"ok": True, "detection": detection},
                    "read_detected": {"ok": False, "error": {"code": "snmp_failure"}},
                }
                if values is None
                else {
                    "detect": {"ok": True, "detection": detection},
                    "read_detected": {
                        "ok": True,
                        "value_count": len(values),
                        "values": values,
                    },
                }
            )

    _add_decodes(dump)
    dump["detection"] = _build_detection_summary(dump["modbus_probes"])
    return _sanitize_data(dump, host, community)


def format_human_report(dump: dict[str, Any]) -> str:
    """Render the diagnostic highlights without raw protocol dumps."""
    lines = ["APC Modbus/SNMP diagnostics"]
    snmp = dump.get("snmp", {})
    sys_name = snmp.get("sysName", {}) if isinstance(snmp, dict) else {}
    if isinstance(sys_name, dict) and "value" in sys_name:
        lines.append(f"SNMP: available ({sys_name['value']})")
    elif dump.get("snmp_availability") == "unavailable":
        lines.append("SNMP: unavailable")
    else:
        lines.append("SNMP: failed; remaining SNMP checks skipped")

    pacing = dump.get("modbus_pacing", {})
    if pacing.get("ok"):
        delay_seconds = dump.get("transport", {}).get(
            "inter_request_delay_seconds", pacing["inter_request_delay_seconds"]
        )
        lines.append(
            "Modbus pacing: "
            f"{pacing['effective_mode']}, "
            f"{delay_seconds}s between requests"
        )
    else:
        lines.append("Modbus pacing: no working connection mode found")

    detection = dump.get("detection", {})
    device_type = detection.get("detected_device_type")
    lines.append(
        f"Device detection: {device_type or 'ambiguous'} "
        f"({detection.get('decision', 'unknown')})"
    )

    if dump.get("modbus_skipped_reason"):
        lines.append(f"Modbus diagnostics: skipped ({dump['modbus_skipped_reason']})")
    else:
        successful_blocks = sum(
            "parsed" in block for block in dump.get("modbus", {}).values()
        )
        lines.append(f"Modbus diagnostics: {successful_blocks} blocks collected")

    external = dump.get("external_probe_tests", {})
    if external.get("skipped_reason"):
        lines.append(f"External probes: skipped ({external['skipped_reason']})")
    elif external.get("detect", {}).get("ok"):
        lines.append("External probes: checked")
    else:
        lines.append("External probes: failed")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the collector CLI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--community", default="public")
    parser.add_argument("--port", type=int, default=MODBUS_TCP_PORT)
    parser.add_argument("--unit", type=int, default=MODBUS_UNIT_ID)
    parser.add_argument(
        "--full-snmp",
        action="store_true",
        help="Collect a full SNMP walk from 1.3.6.1 in addition to targeted probes",
    )
    parser.add_argument(
        "--snmp-unavailable",
        action="store_true",
        help="Skip SNMP collection when the device has no reachable SNMP service",
    )
    parser.add_argument(
        "--human",
        action="store_true",
        help="Print a concise human-readable summary instead of JSON",
    )
    parser.add_argument(
        "--request-delay-seconds",
        type=float,
        help="Override the diagnosed delay between Modbus diagnostic requests",
    )
    args = parser.parse_args()
    if args.request_delay_seconds is not None and (
        args.request_delay_seconds < 0
        or not math.isfinite(args.request_delay_seconds)
    ):
        parser.error("--request-delay-seconds must be a finite non-negative number")
    return args


def main() -> int:
    """Run the collector CLI."""
    args = parse_args()
    dump = collect_diagnostic_dump(
        host=args.host,
        community=args.community,
        port=args.port,
        unit_id=args.unit,
        full_snmp=args.full_snmp,
        snmp_availability="unavailable" if args.snmp_unavailable else "unknown",
        request_delay_seconds=args.request_delay_seconds,
    )
    output = format_human_report(dump) if args.human else json.dumps(dump, indent=2)
    sys.stdout.write(f"{output}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
