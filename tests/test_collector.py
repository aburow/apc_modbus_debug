# SPDX-FileCopyrightText: 2026 aburow
# SPDX-License-Identifier: GPL-3.0-only

"""Pytest coverage for collector.py."""

from __future__ import annotations

import asyncio
import struct
from datetime import UTC, datetime

import pytest

import collector


def make_modbus_response(*registers: int, unit_id: int = 1) -> bytes:
    """Build a Modbus TCP holding-register response for tests."""
    byte_count = len(registers) * 2
    payload = bytes([3, byte_count])
    payload += b"".join(struct.pack(">H", register) for register in registers)
    length = len(payload) + 1
    header = struct.pack(">HHHB", 1, 0, length, unit_id)
    return header + payload


def test_parse_modbus_response_returns_registers() -> None:
    """A valid Modbus response should decode into registers."""
    response = make_modbus_response(0x0001, 0x00FF, 0x1234, unit_id=7)

    parsed = collector._parse_modbus_response(response)

    assert parsed == {"unit_id": 7, "registers": [1, 255, 0x1234]}


def test_parse_modbus_response_handles_exception_frame() -> None:
    """A Modbus exception frame should surface the exception code."""
    header = struct.pack(">HHHB", 1, 0, 3, 1)
    response = header + bytes([0x83, 0x02])

    parsed = collector._parse_modbus_response(response)

    assert parsed == {
        "error": {
            "code": "modbus_exception",
            "message": "Modbus exception 2: Illegal Data Address",
            "exception_code": 2,
            "exception_name": "Illegal Data Address",
        }
    }


def test_decode_ascii_registers_uses_low_byte_only() -> None:
    """ASCII register decoding should ignore high bytes and nulls."""
    registers = [0x0141, 0x0042, 0x0000, 0x7E43]

    decoded = collector._decode_ascii_registers(registers)

    assert decoded == "ABC"


def test_build_quick_decode_returns_scaled_values() -> None:
    """The 0x0080 block quick decode should apply documented scaling."""
    registers = [0] * 26
    registers[collector._block_index(0x0080)] = 0
    registers[collector._block_index(0x0080) + 1] = 600
    registers[collector._block_index(0x0082)] = 51200
    registers[collector._block_index(0x0083)] = 3200
    registers[collector._block_index(0x0084)] = 0xFE00
    registers[collector._block_index(0x0087)] = 25 * 128
    registers[collector._block_index(0x0088)] = 128
    registers[collector._block_index(0x008C)] = 64
    registers[collector._block_index(0x008E)] = 14720
    registers[collector._block_index(0x0090)] = 6400
    registers[collector._block_index(0x0091)] = 0
    registers[collector._block_index(0x0091) + 1] = 12345
    registers[collector._block_index(0x0097)] = 15104

    quick = collector._build_quick_decode(registers)

    assert quick == {
        "runtime_remaining": 600,
        "soc_pct": 100.0,
        "batt_v_pos": 100.0,
        "batt_v_neg": -16.0,
        "batt_temp_c": 25.0,
        "out_load_pct": 0.5,
        "out_current": 2.0,
        "out_voltage": 230.0,
        "out_freq": 50.0,
        "out_energy_wh": 12345,
        "in_voltage": 236.0,
    }


def test_add_decodes_attaches_quick_and_identity_data() -> None:
    """Known runtime and identity blocks should gain decoded helpers."""
    dump: dict[str, object] = {
        "modbus": {
            collector.RUNTIME_BLOCK_KEY: {
                "parsed": {
                    "registers": [
                        0,
                        600,
                        51200,
                        3200,
                        0xFE00,
                        0,
                        0,
                        25 * 128,
                        128,
                        0,
                        0,
                        0,
                        64,
                        0,
                        14720,
                        0,
                        6400,
                        0,
                        12345,
                        0,
                        0,
                        0,
                        0,
                        15104,
                        0,
                        0,
                    ]
                }
            },
            collector.LEGACY_ID_BLOCK_KEY: {
                "parsed": {
                    "registers": [0, ord("S"), ord("U"), ord("7"), ord("0"), ord("0"), 0, 0, 0, 0]
                }
            },
            collector.MODERN_ID_BLOCK_KEY: {
                "parsed": {
                    "registers": [
                        ord("F"),
                        ord("W"),
                        ord("7"),
                        ord("."),
                        ord("2"),
                        ord("."),
                        ord("0"),
                        0,
                        ord("S"),
                        ord("M"),
                        ord("X"),
                        ord("1"),
                        ord("5"),
                        ord("0"),
                        ord("0"),
                        0,
                        ord("S"),
                        ord("N"),
                        ord("1"),
                        ord("2"),
                        ord("3"),
                    ]
                }
            },
        }
    }

    collector._add_decodes(dump)

    runtime = dump["modbus"][collector.RUNTIME_BLOCK_KEY]
    legacy = dump["modbus"][collector.LEGACY_ID_BLOCK_KEY]
    modern = dump["modbus"][collector.MODERN_ID_BLOCK_KEY]
    assert runtime["quick_decode"]["out_voltage"] == 230.0
    assert legacy["identity_decode"] == {"legacy_ups_id": "SU700"}
    assert modern["identity_decode"] == {
        "ascii_chunks": {
            "0x023C": "FW7.2.0",
            "0x0244": "SMX1500",
            "0x024C": "SN123",
        }
    }


def test_collect_snmp_data_maps_success_missing_and_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SNMP collection should produce value/missing/exception payloads."""

    calls = {"count": 0}

    def fake_snmpget(host: str, community: str, oid: str) -> str | None:
        del host, community
        calls["count"] += 1
        if oid == collector.SNMP_OIDS["sysName"]:
            return "test-device"
        if oid == collector.SNMP_OIDS["sysDescr"]:
            raise RuntimeError("boom")
        return None

    monkeypatch.setattr(collector, "_snmpget_value", fake_snmpget)

    result = asyncio.run(collector._collect_snmp_data("192.0.2.10", "public"))

    assert calls["count"] == len(collector.SNMP_OIDS)
    assert result["sysName"] == {
        "oid": collector.SNMP_OIDS["sysName"],
        "value": "test-device",
    }
    assert result["sysDescr"] == {
        "oid": collector.SNMP_OIDS["sysDescr"],
        "error": {
            "code": "snmp_exception",
            "message": "boom",
            "exception_type": "RuntimeError",
        },
    }
    assert result["apc_model_smartups"] == {
        "oid": collector.SNMP_OIDS["apc_model_smartups"],
        "error": {"code": "snmp_missing", "message": "No value returned"},
    }


def test_collect_modbus_block_returns_error_payload_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I/O failures should remain structured block errors."""

    def fail(*_args: object, **_kwargs: object) -> bytes:
        raise RuntimeError("Short PDU")

    monkeypatch.setattr(collector, "_modbus_read_holding_registers", fail)

    block = collector._collect_modbus_block("192.0.2.10", 502, 1, 0x0000, 4)

    assert block == {
        "error": {
            "code": "modbus_block_read_failed",
            "message": "Short PDU",
            "exception_type": "RuntimeError",
        }
    }


def test_collect_diagnostic_dump_redacts_and_adds_decodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Top-level collection should match HA collector semantics."""

    def fake_asyncio_run(coroutine: object) -> dict[str, object]:
        coroutine.close()
        return {
            "sysName": {
                "oid": collector.SNMP_OIDS["sysName"],
                "value": "device-192.0.2.10 public serial: ABC123",
            }
        }

    def fake_collect_modbus_block(
        host: str,
        port: int,
        unit_id: int,
        start: int,
        count: int,
    ) -> dict[str, object]:
        assert host == "192.0.2.10"
        assert port == 502
        assert unit_id == 1
        if start == 0x0080:
            return {
                "start": start,
                "count": count,
                "raw_hex": "quick",
                "parsed": {
                    "unit_id": 1,
                    "registers": [
                        0,
                        600,
                        51200,
                        3200,
                        0xFE00,
                        0,
                        0,
                        25 * 128,
                        128,
                        0,
                        0,
                        0,
                        64,
                        0,
                        14720,
                        0,
                        6400,
                        0,
                        12345,
                        0,
                        0,
                        0,
                        0,
                        15104,
                        0,
                        0,
                    ],
                },
            }
        if start == 0x0021:
            return {
                "start": start,
                "count": count,
                "raw_hex": "legacy",
                "parsed": {
                    "unit_id": 1,
                    "registers": [0, ord("S"), ord("U"), ord("7"), ord("0"), ord("0"), 0, 0, 0, 0],
                },
            }
        if start == 0x023C:
            return {
                "start": start,
                "count": count,
                "raw_hex": "modern",
                "parsed": {
                    "unit_id": 1,
                    "registers": [
                        ord("F"),
                        ord("W"),
                        ord("7"),
                        ord("."),
                        ord("2"),
                        ord("."),
                        ord("0"),
                        0,
                        ord("S"),
                        ord("M"),
                        ord("X"),
                        ord("1"),
                        ord("5"),
                        ord("0"),
                        ord("0"),
                        0,
                        ord("S"),
                        ord("N"),
                        ord("1"),
                        ord("2"),
                        ord("3"),
                    ],
                },
            }
        return {
            "start": start,
            "count": count,
            "raw_hex": "base",
            "parsed": {"unit_id": 1, "registers": [1, 2, 3]},
        }

    monkeypatch.setattr(collector.asyncio, "run", fake_asyncio_run)
    monkeypatch.setattr(collector, "_collect_modbus_block", fake_collect_modbus_block)

    dump = collector.collect_diagnostic_dump("192.0.2.10", "public", 502, 1)

    assert dump["host"] == collector.REDACTED_IP
    assert dump["port"] == 502
    assert dump["unit_id"] == 1
    assert datetime.fromisoformat(dump["generated_at"]).tzinfo == UTC
    assert set(dump["modbus"]) == {
        "0x0000_count_23",
        "0x0080_count_26",
        "0x0021_count_10",
        "0x009E_count_5",
        "0x00CF_count_6",
        "0x023C_count_21",
    }
    assert dump["modbus"][collector.RUNTIME_BLOCK_KEY]["quick_decode"]["out_voltage"] == 230.0
    assert dump["modbus"][collector.LEGACY_ID_BLOCK_KEY]["identity_decode"] == {
        "legacy_ups_id": "SU700"
    }
    assert dump["modbus"][collector.MODERN_ID_BLOCK_KEY]["identity_decode"] == {
        "ascii_chunks": {
            "0x023C": "FW7.2.0",
            "0x0244": "SMX1500",
            "0x024C": "SN123",
        }
    }
    assert dump["snmp"]["sysName"]["oid"] == collector.SNMP_OIDS["sysName"]
    assert dump["snmp"]["sysName"]["value"] == (
        f"device-{collector.REDACTED_IP} {collector.REDACTED_COMMUNITY} "
        f"serial: {collector.REDACTED_SERIAL}"
    )
