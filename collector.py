# SPDX-FileCopyrightText: 2026 aburow
# SPDX-License-Identifier: GPL-3.0-only

"""Collect SNMP and Modbus data from an APC device."""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import struct
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, TypedDict, cast

MBAP_HEADER_LENGTH: Final[int] = 7
MIN_MODBUS_RESPONSE_LENGTH: Final[int] = 9
MODBUS_EXCEPTION_FLAG: Final[int] = 0x80
INT16_SIGN_BIT: Final[int] = 0x8000
INT16_MODULUS: Final[int] = 0x10000
ASCII_PRINTABLE_START: Final[int] = 32
ASCII_PRINTABLE_END: Final[int] = 126
RUNTIME_BLOCK_KEY: Final[str] = "0x0080_count_26"
LEGACY_ID_BLOCK_KEY: Final[str] = "0x0021_count_10"
MODERN_ID_BLOCK_KEY: Final[str] = "0x023C_count_21"
MODBUS_TCP_PORT: Final[int] = 502
MODBUS_UNIT_ID: Final[int] = 1
SNMP_TIMEOUT_SECONDS: Final[int] = 10
MODBUS_TIMEOUT_SECONDS: Final[int] = 5
MODBUS_EXCEPTION_NAMES: Final[dict[int, str]] = {
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


class ErrorInfo(TypedDict, total=False):

    """Human- and machine-readable error payload."""

    code: str
    message: str
    raw: str
    exception_type: str
    exception_code: int
    exception_name: str


class SnmpResult(TypedDict, total=False):

    """Result payload for an SNMP query."""

    raw: str
    error: ErrorInfo


class ModbusParsedSuccess(TypedDict):

    """Successful parsed Modbus response."""

    unit_id: int
    registers: list[int]


class ModbusParsedError(TypedDict):

    """Failed parsed Modbus response."""

    error: ErrorInfo


ModbusParsed = ModbusParsedSuccess | ModbusParsedError


class ModbusReadSuccess(TypedDict):

    """Successful raw and parsed Modbus block."""

    start: int
    count: int
    raw_hex: str
    parsed: ModbusParsed


class ModbusReadError(TypedDict):

    """Failed Modbus block read."""

    error: ErrorInfo


class QuickDecode(TypedDict):

    """Convenience values decoded from the 0x0080 block."""

    runtime_remaining: int | None
    soc_pct: float | None
    batt_v_pos: float | None
    batt_v_neg: float | None
    batt_temp_c: float | None
    out_load_pct: float | None
    out_current: float | None
    out_voltage: float | None
    out_freq: float | None
    out_energy_wh: int | None
    in_voltage: float | None


class IdentityDecode(TypedDict, total=False):

    """Best-effort identity strings decoded from Modbus registers."""

    legacy_ups_id: str
    ascii_chunks: dict[str, str]


class ModbusReadSuccessWithQuickDecode(ModbusReadSuccess):

    """Successful raw and parsed Modbus block with quick decode."""

    quick_decode: QuickDecode


class ModbusReadSuccessWithIdentityDecode(ModbusReadSuccess):

    """Successful raw and parsed Modbus block with decoded identity hints."""

    identity_decode: IdentityDecode


ModbusBlock = (
    ModbusReadSuccess
    | ModbusReadSuccessWithQuickDecode
    | ModbusReadSuccessWithIdentityDecode
    | ModbusReadError
)


class Dump(TypedDict):

    """Top-level output payload."""

    generated_at: str
    host: str
    port: int
    unit_id: int
    snmp: dict[str, SnmpResult]
    modbus: dict[str, ModbusBlock]


@dataclass(frozen=True)
class ModbusRequest:

    """Parameters for a single Modbus TCP holding-register read."""

    host: str
    port: int
    unit_id: int
    address: int
    count: int
    timeout: int = MODBUS_TIMEOUT_SECONDS


SNMP_OIDS: Final[dict[str, str]] = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "apc_model_smartups": "1.3.6.1.4.1.318.1.1.1.1.1.1.0",
    "apc_model_rackpdu": "1.3.6.1.4.1.318.1.1.12.1.5.0",
    "apc_serial": "1.3.6.1.4.1.318.1.1.1.1.2.3.0",
    "apc_fw": "1.3.6.1.4.1.318.1.1.1.1.2.1.0",
    "apc_fw_date": "1.3.6.1.4.1.318.1.1.1.1.2.2.0",
}

MODBUS_BLOCKS: Final[list[tuple[int, int]]] = [
    (0x0000, 0x0016 - 0x0000 + 1),
    (0x0080, 0x0099 - 0x0080 + 1),
    (0x0021, 0x002A - 0x0021 + 1),
    (0x023C, 0x0250 - 0x023C + 1),
]


def run_snmpget(host: str, community: str, oid: str) -> SnmpResult:
    """Run `snmpget` for a single OID and capture the raw response."""
    snmpget_path = shutil.which("snmpget")
    if snmpget_path is None:
        return {
            "error": {
                "code": "snmpget_missing_binary",
                "message": "snmpget not found",
            },
        }

    cmd = [snmpget_path, "-v", "2c", "-c", community, host, oid]
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            cmd,
            capture_output=True,
            check=True,
            text=True,
            timeout=SNMP_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as exc:
        return {
            "error": {
                "code": "snmpget_failed",
                "message": "snmpget command failed",
                "raw": exc.stdout.strip() or exc.stderr.strip(),
                "exception_type": type(exc).__name__,
            },
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "error": {
                "code": "snmpget_runtime_error",
                "message": str(exc),
                "exception_type": type(exc).__name__,
            },
        }

    return {"raw": completed.stdout.strip()}


def modbus_read_holding_registers(request: ModbusRequest) -> bytes:
    """Read a block of holding registers over Modbus TCP."""
    transaction_id = 1
    protocol_id = 0
    request_length = 6
    function_code = 3
    mbap_header = struct.pack(
        ">HHHB",
        transaction_id,
        protocol_id,
        request_length,
        request.unit_id,
    )
    pdu = struct.pack(">BHH", function_code, request.address, request.count)
    payload_request = mbap_header + pdu

    with socket.create_connection(
        (request.host, request.port),
        timeout=request.timeout,
    ) as connection:
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


def parse_modbus_response(response: bytes) -> ModbusParsed:
    """Decode a Modbus TCP response into registers or an error."""
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


def decode_uint32(registers: list[int], index: int) -> int | None:
    """Decode two 16-bit registers as an unsigned 32-bit value."""
    if index + 1 >= len(registers):
        return None
    return (registers[index] << 16) | registers[index + 1]


def decode_int16(value: int) -> int:
    """Decode a 16-bit register as a signed integer."""
    return value - INT16_MODULUS if value >= INT16_SIGN_BIT else value


def decode_ascii_registers(registers: list[int]) -> str:
    """Decode single-byte ASCII stored in 16-bit registers."""
    chars: list[str] = []
    for register in registers:
        code_point = register & 0xFF
        if not code_point:
            continue
        if ASCII_PRINTABLE_START <= code_point <= ASCII_PRINTABLE_END:
            chars.append(chr(code_point))

    return "".join(chars).strip()


def block_index(address: int) -> int:
    """Map an absolute register address into the 0x0080 block."""
    return address - 0x0080


def scaled_register(
    registers: list[int],
    address: int,
    divisor: int,
    *,
    signed: bool = False,
) -> float | None:
    """Return a scaled register value when the address exists."""
    index = block_index(address)
    if len(registers) <= index:
        return None

    value = decode_int16(registers[index]) if signed else registers[index]
    return value / divisor


def build_quick_decode(registers: list[int]) -> QuickDecode:
    """Build convenience metrics from the 0x0080 Modbus block."""
    return {
        "runtime_remaining": decode_uint32(registers, block_index(0x0080)),
        "soc_pct": scaled_register(registers, 0x0082, 512),
        "batt_v_pos": scaled_register(registers, 0x0083, 32, signed=True),
        "batt_v_neg": scaled_register(registers, 0x0084, 32, signed=True),
        "batt_temp_c": scaled_register(registers, 0x0087, 128, signed=True),
        "out_load_pct": scaled_register(registers, 0x0088, 256),
        "out_current": scaled_register(registers, 0x008C, 32),
        "out_voltage": scaled_register(registers, 0x008E, 64),
        "out_freq": scaled_register(registers, 0x0090, 128),
        "out_energy_wh": decode_uint32(registers, block_index(0x0091)),
        "in_voltage": scaled_register(registers, 0x0097, 64),
    }


def build_identity_decode(
    block_key: str,
    registers: list[int],
) -> IdentityDecode | None:
    """Build best-effort identity hints for known Modbus ID blocks."""
    if block_key == LEGACY_ID_BLOCK_KEY:
        legacy_ups_id = decode_ascii_registers(registers[1:9])
        if not legacy_ups_id:
            return None
        return {"legacy_ups_id": legacy_ups_id}

    if block_key == MODERN_ID_BLOCK_KEY:
        ascii_chunks = {
            f"0x{0x023C + index:04X}": decoded
            for index in range(0, len(registers), 8)
            if (decoded := decode_ascii_registers(registers[index : index + 8]))
        }
        if not ascii_chunks:
            return None
        return {"ascii_chunks": ascii_chunks}

    return None


def collect_modbus_block(
    host: str,
    port: int,
    unit_id: int,
    start: int,
    count: int,
) -> ModbusBlock:
    """Collect and parse one Modbus block."""
    request = ModbusRequest(
        host=host,
        port=port,
        unit_id=unit_id,
        address=start,
        count=count,
    )
    try:
        raw = modbus_read_holding_registers(request)
        parsed = parse_modbus_response(raw)
    except (OSError, RuntimeError, struct.error) as exc:
        return {
            "error": {
                "code": "modbus_block_read_failed",
                "message": str(exc),
                "exception_type": type(exc).__name__,
            },
        }

    return {
        "start": start,
        "count": count,
        "raw_hex": raw.hex(),
        "parsed": parsed,
    }


def add_quick_decode(dump: Dump) -> None:
    """Attach quick-decoded values when the runtime block is present."""
    runtime_block = dump["modbus"].get(RUNTIME_BLOCK_KEY)
    if runtime_block is None or "parsed" not in runtime_block:
        return

    parsed = runtime_block["parsed"]
    if "registers" not in parsed:
        return

    registers = parsed["registers"]
    if not registers:
        return

    runtime_block_with_decode = cast("ModbusReadSuccessWithQuickDecode", runtime_block)
    runtime_block_with_decode["quick_decode"] = build_quick_decode(registers)


def add_identity_decodes(dump: Dump) -> None:
    """Attach identity-oriented decodes for known Modbus ID blocks."""
    for block_key in (LEGACY_ID_BLOCK_KEY, MODERN_ID_BLOCK_KEY):
        modbus_block = dump["modbus"].get(block_key)
        if modbus_block is None or "parsed" not in modbus_block:
            continue

        parsed = modbus_block["parsed"]
        if "registers" not in parsed:
            continue

        identity_decode = build_identity_decode(block_key, parsed["registers"])
        if identity_decode is None:
            continue

        block_with_identity = cast("ModbusReadSuccessWithIdentityDecode", modbus_block)
        block_with_identity["identity_decode"] = identity_decode


def build_dump(host: str, community: str, port: int, unit_id: int) -> Dump:
    """Collect SNMP and Modbus data and return the output payload."""
    dump: Dump = {
        "generated_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "host": host,
        "port": port,
        "unit_id": unit_id,
        "snmp": {},
        "modbus": {},
    }

    for name, oid in SNMP_OIDS.items():
        dump["snmp"][name] = run_snmpget(host, community, oid)

    for start, count in MODBUS_BLOCKS:
        key = f"0x{start:04X}_count_{count}"
        dump["modbus"][key] = collect_modbus_block(
            host=host,
            port=port,
            unit_id=unit_id,
            start=start,
            count=count,
        )

    add_quick_decode(dump)
    add_identity_decodes(dump)
    return dump


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the collector."""
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--community", default="public")
    parser.add_argument("--port", type=int, default=MODBUS_TCP_PORT)
    parser.add_argument("--unit", type=int, default=MODBUS_UNIT_ID)
    return parser.parse_args()


def main() -> int:
    """Run the collector CLI."""
    args = parse_args()
    dump = build_dump(
        host=args.host,
        community=args.community,
        port=args.port,
        unit_id=args.unit,
    )
    sys.stdout.write(f"{json.dumps(dump, indent=2)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
