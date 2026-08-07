import importlib.util
import struct
import sys
from contextlib import nullcontext
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "modbus_test", Path(__file__).parent.parent / "modbus-test.py"
)
assert SPEC and SPEC.loader
MODBUS_TEST = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODBUS_TEST
SPEC.loader.exec_module(MODBUS_TEST)


def test_smartconnect_ups_detection() -> None:
    probes = {
        "rack_pdu_capabilities": {"parsed": {"error": {"code": "modbus_exception", "exception_code": 2}}},
        "rack_pdu_measurements": {"parsed": {"registers": [0xFFFF] * 6}},
        "legacy_ups_id": {"parsed": {"registers": [0xFFFF]}},
        "smt_status": {"parsed": {"registers": [0, 8194] + [0] * 21}},
        "smt_measurements": {"parsed": {"registers": [0, 4845] + [0xFFFF] * 24}},
    }
    result = MODBUS_TEST.detect_device(probes)
    assert result["detected_device_type"] == "smartconnect_ups"
    assert result["decision"] == "definitive"


def test_parse_modbus_registers() -> None:
    response = struct.pack(">HHHBBBH", 1, 0, 5, 1, 3, 2, 50)
    assert MODBUS_TEST.parse_response(response)["registers"] == [50]


def test_recv_exact_handles_fragmented_tcp_reads() -> None:
    class FragmentedSocket:
        def __init__(self) -> None:
            self.chunks = [b"ab", b"c", b"def"]

        def recv(self, _size: int) -> bytes:
            return self.chunks.pop(0)

    assert MODBUS_TEST.recv_exact(FragmentedSocket(), 6) == b"abcdef"


def test_manual_delay_is_used_by_pacing_preflight(monkeypatch) -> None:
    monkeypatch.setattr(
        MODBUS_TEST.socket,
        "create_connection",
        lambda *args, **kwargs: nullcontext(object()),
    )
    monkeypatch.setattr(MODBUS_TEST, "read_holding_registers", lambda *args: b"")
    monkeypatch.setattr(MODBUS_TEST.time, "sleep", lambda *_: None)
    result = MODBUS_TEST.diagnose_pacing("127.0.0.1", 502, 1, 3)
    assert result["attempts"] == [
        {"mode": "session", "request_delay_seconds": 3, "ok": True}
    ]


def test_persistent_connection_failure_stops_remaining_blocks(monkeypatch) -> None:
    class Connection:
        def close(self) -> None:
            pass

    monkeypatch.setattr(
        MODBUS_TEST,
        "diagnose_pacing",
        lambda *args: {
            "ok": True,
            "effective_mode": "session",
            "inter_request_delay_seconds": 0,
            "attempts": [],
        },
    )
    monkeypatch.setattr(
        MODBUS_TEST.socket, "create_connection", lambda *args, **kwargs: Connection()
    )
    calls: list[object] = []
    monkeypatch.setattr(
        MODBUS_TEST,
        "collect_block",
        lambda *args: calls.append(args) or {"error": {"code": "read_failed"}},
    )
    result = MODBUS_TEST.collect("127.0.0.1", 502, 1, None)
    assert len(calls) == 1
    assert result["modbus_skipped_reason"] == "persistent_connection_failed"


def test_invalid_delay_is_rejected() -> None:
    for delay in (float("nan"), -1):
        try:
            MODBUS_TEST.collect("127.0.0.1", 502, 1, delay)
        except ValueError as err:
            assert "finite non-negative" in str(err)
        else:
            raise AssertionError(f"invalid delay {delay!r} was accepted")
