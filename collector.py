# SPDX-License-Identifier: GPL-3.0
# Copyright (C) 2026 Anthony Burow
# https://github.com/aburow/apc-modbus-snmp-ha

"""On-demand diagnostics collector for APC devices (standalone CLI)."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
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
MODBUS_IDLE_STAGES = (5, 10, 30, 60)
MODBUS_IDLE_PROBE_ADDRESS = 0x0000
MODBUS_IDLE_PROBE_COUNT = 1
SNMP_FULL_WALK_ROOT = "1.3.6.1"
SNMP_FULL_WALK_TIMEOUT_SECONDS = 60
SNMP_INPUT_FREQUENCY_THRESHOLD = 400
SNMP_INPUT_FREQUENCY_MIN_HZ = 40.0
SNMP_INPUT_FREQUENCY_MAX_HZ = 70.0
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
}

MODBUS_BLOCKS: list[tuple[int, int]] = [
    (0x0000, 0x0016 - 0x0000 + 1),
    (0x0080, 0x0099 - 0x0080 + 1),
    (0x0021, 0x002A - 0x0021 + 1),
    (0x009E, 0x00A2 - 0x009E + 1),
    (0x00CF, 0x00D4 - 0x00CF + 1),
    (0x023C, 0x0250 - 0x023C + 1),
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
    match = NUMERIC_VALUE_RE.search(str(value))
    if not match:
        return None
    try:
        return float(match.group(0))
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
    if raw > SNMP_INPUT_FREQUENCY_THRESHOLD:
        raw = raw / 10.0
    if raw < SNMP_INPUT_FREQUENCY_MIN_HZ or raw > SNMP_INPUT_FREQUENCY_MAX_HZ:
        return None
    return raw


def _detect_device_type_from_model(model: str | None) -> str:
    if not model:
        return "smart_ups"
    model_upper = model.upper()
    if (
        "AP8" in model_upper
        or model_upper.startswith("APDU")
        or "RACK PDU" in model_upper
    ):
        return "rack_pdu"
    if (
        model_upper.startswith("SMT")
        or model_upper.startswith("SMX")
        or model_upper.startswith("SRT")
        or "SMART-UPS X" in model_upper
        or "SMART UPS X" in model_upper
        or "SMART-UPS SMT" in model_upper
        or "SMART-UPS SMX" in model_upper
        or "SMART-UPS SRT" in model_upper
    ):
        return "smt_ups"
    if "SMART-UPS" in model_upper or "SMART UPS" in model_upper:
        return "smart_ups"
    return "smart_ups"


def _build_device_detection_summary(snmp_data: dict[str, Any], modbus_data: dict[str, Any]) -> dict[str, Any]:
    model_value = snmp_data.get("apc_model_smartups", {}).get("value")
    rack_model_value = snmp_data.get("apc_model_rackpdu", {}).get("value")
    detected_from_snmp = _detect_device_type_from_model(
        rack_model_value if rack_model_value and rack_model_value != "No Such Object available on this agent at this OID" else model_value
    )

    probe_results = {
        "rack_pdu_capabilities_ok": _probe_block_ok(modbus_data.get("0x009E_count_5"), 5),
        "rack_pdu_measurements_ok": _probe_block_ok(modbus_data.get("0x00CF_count_6"), 6),
        "legacy_probe_ok": _probe_block_ok(modbus_data.get("0x0021_count_10"), 10),
        "smt_status_ok": _probe_block_ok(modbus_data.get("0x0000_count_23"), 23),
        "smt_measurements_ok": _probe_block_ok(modbus_data.get("0x0080_count_26"), 26),
    }

    if probe_results["rack_pdu_capabilities_ok"] and probe_results["rack_pdu_measurements_ok"]:
        detected_from_modbus = "rack_pdu"
    elif probe_results["smt_measurements_ok"] and not probe_results["legacy_probe_ok"]:
        detected_from_modbus = "smt_ups"
    elif probe_results["legacy_probe_ok"] and not probe_results["smt_measurements_ok"]:
        detected_from_modbus = "smart_ups"
    else:
        detected_from_modbus = None

    return {
        "device_type": detected_from_modbus or detected_from_snmp,
        "device_type_source": "modbus" if detected_from_modbus else "snmp",
        "snmp_model": model_value if detected_from_snmp != "rack_pdu" else rack_model_value,
        "probe_results": probe_results,
    }


def _detect_external_probe_oids(host: str, community: str) -> dict[str, str | None]:
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
) -> dict[str, Any]:
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
        values[key] = (
            parser(_snmpget_value(host, community, selected_oid))
            if selected_oid
            else None
        )

    frequency_raw = None
    frequency_source_oid = None
    for candidate_oid in SNMP_INPUT_FREQUENCY_OID_CANDIDATES:
        raw_value = _snmpget_value(host, community, candidate_oid)
        if raw_value is None:
            continue
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


def _probe_block_ok(modbus_block: dict[str, Any] | None, count: int) -> bool:
    """Return True when a collected Modbus block contains a successful read."""
    if not modbus_block or "parsed" not in modbus_block:
        return False
    parsed = modbus_block["parsed"]
    registers = parsed.get("registers")
    return isinstance(registers, list) and len(registers) == count


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
    header = connection.recv(MBAP_HEADER_LENGTH)
    if len(header) < MBAP_HEADER_LENGTH:
        msg = "Short MBAP header"
        raise RuntimeError(msg)

    _, _, response_length, _ = struct.unpack(">HHHB", header)
    payload = connection.recv(response_length - 1)
    if len(payload) < (response_length - 1):
        msg = "Short PDU"
        raise RuntimeError(msg)

    return header + payload


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


def _run_modbus_tcp_idle_probe(host: str, port: int, unit_id: int) -> dict[str, Any]:
    """Check whether a single Modbus TCP session survives staged idle waits."""
    result: dict[str, Any] = {
        "enabled": True,
        "address": MODBUS_IDLE_PROBE_ADDRESS,
        "count": MODBUS_IDLE_PROBE_COUNT,
        "stage_seconds": list(MODBUS_IDLE_STAGES),
        "stages": [],
    }

    try:
        with socket.create_connection((host, port), timeout=MODBUS_TIMEOUT_SECONDS) as connection:
            first_raw = _modbus_read_holding_registers_on_connection(
                connection,
                unit_id,
                MODBUS_IDLE_PROBE_ADDRESS,
                MODBUS_IDLE_PROBE_COUNT,
            )
            first_parsed = _parse_modbus_response(first_raw)
            result["initial_read"] = {"ok": "error" not in first_parsed}

            elapsed_seconds = 0
            for index, stage_seconds in enumerate(MODBUS_IDLE_STAGES, start=1):
                wait_seconds = stage_seconds - elapsed_seconds
                sys.stderr.write(
                    f"Idle timer check {index}/{len(MODBUS_IDLE_STAGES)}: "
                    f"waiting {wait_seconds}s to reach {stage_seconds}s\n"
                )
                sys.stderr.flush()
                if wait_seconds > 0:
                    time.sleep(wait_seconds)

                try:
                    raw = _modbus_read_holding_registers_on_connection(
                        connection,
                        unit_id,
                        MODBUS_IDLE_PROBE_ADDRESS,
                        MODBUS_IDLE_PROBE_COUNT,
                    )
                    parsed = _parse_modbus_response(raw)
                    stage_ok = "error" not in parsed
                    result["stages"].append(
                        {
                            "idle_seconds_tested": stage_seconds,
                            "wait_seconds": wait_seconds,
                            "ok": stage_ok,
                            "socket_survived_idle": stage_ok,
                            "parsed": parsed,
                        }
                    )
                    elapsed_seconds = stage_seconds
                    sys.stderr.write(
                        f"Idle timer check {index}/{len(MODBUS_IDLE_STAGES)} "
                        f"passed at {stage_seconds}s\n"
                    )
                    sys.stderr.flush()
                except (OSError, RuntimeError, struct.error) as err:
                    result["stages"].append(
                        {
                            "idle_seconds_tested": stage_seconds,
                            "wait_seconds": wait_seconds,
                            "ok": False,
                            "socket_survived_idle": False,
                            "error": {
                                "code": "modbus_idle_reuse_failed",
                                "message": str(err),
                                "exception_type": type(err).__name__,
                            },
                        }
                    )
                    result["socket_survived_idle"] = False
                    result["failed_stage_seconds"] = stage_seconds
                    result["failed_stage_index"] = index
                    sys.stderr.write(
                        f"Idle timer check {index}/{len(MODBUS_IDLE_STAGES)} failed at "
                        f"{stage_seconds}s\n"
                    )
                    sys.stderr.flush()
                    for skipped_stage in MODBUS_IDLE_STAGES[index:]:
                        result["stages"].append(
                            {
                                "idle_seconds_tested": skipped_stage,
                                "skipped": True,
                                "skipped_reason": "previous_stage_failed",
                            }
                        )
                    break
            else:
                result["socket_survived_idle"] = True
    except (OSError, RuntimeError, struct.error) as err:
        result["socket_survived_idle"] = False
        result["error"] = {
            "code": "modbus_idle_probe_failed",
            "message": str(err),
            "exception_type": type(err).__name__,
        }

    return result


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
    values = await asyncio.gather(
        *(
            asyncio.to_thread(_snmpget_value, host, community, oid)
            for oid in SNMP_OIDS.values()
        ),
        return_exceptions=True,
    )
    result: dict[str, Any] = {}
    for key, oid, value in zip(
        SNMP_OIDS.keys(), SNMP_OIDS.values(), values, strict=False,
    ):
        if isinstance(value, Exception):
            result[key] = {
                "oid": oid,
                "error": {
                    "code": "snmp_exception",
                    "message": str(value),
                    "exception_type": type(value).__name__,
                },
            }
            continue
        if value is None:
            result[key] = {
                "oid": oid,
                "error": {"code": "snmp_missing", "message": "No value returned"},
            }
            continue
        result[key] = {"oid": oid, "value": value}
    return result


def _collect_modbus_block(
    host: str,
    port: int,
    unit_id: int,
    start: int,
    count: int,
) -> dict[str, Any]:
    try:
        raw = _modbus_read_holding_registers(host, port, unit_id, start, count)
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
) -> dict[str, Any]:
    """Collect SNMP and Modbus diagnostic data for one APC device."""
    snmp_data = asyncio.run(_collect_snmp_data(host, community))
    snmp_full: dict[str, Any] | None = None
    if full_snmp:
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
        "modbus_tcp_idle_probe": _run_modbus_tcp_idle_probe(host, port, unit_id),
    }
    if snmp_full is not None:
        dump["snmp_full"] = snmp_full

    for start, count in MODBUS_BLOCKS:
        key = f"0x{start:04X}_count_{count}"
        dump["modbus"][key] = _collect_modbus_block(host, port, unit_id, start, count)

    dump["detection"] = _build_device_detection_summary(snmp_data, dump["modbus"])
    external_detection = _detect_external_probe_oids(host, community)
    dump["external_probe_detection"] = external_detection
    dump["external_probe_data"] = _collect_external_probe_data(
        host, community, external_detection
    )

    _add_decodes(dump)
    return _sanitize_data(dump, host, community)


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
    return parser.parse_args()


def main() -> int:
    """Run the collector CLI."""
    args = parse_args()
    dump = collect_diagnostic_dump(
        host=args.host,
        community=args.community,
        port=args.port,
        unit_id=args.unit,
        full_snmp=args.full_snmp,
    )
    sys.stdout.write(f"{json.dumps(dump, indent=2)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
