from contextlib import nullcontext

import collector

def response(values: list[int]) -> dict[str, object]:
    return {"parsed": {"registers": values}}


def exception() -> dict[str, object]:
    return {"parsed": {"error": {"code": "modbus_exception", "exception_code": 2}}}


def test_smartconnect_ups_detection() -> None:
    summary = collector._build_detection_summary(
        {
            "rack_pdu_capabilities": exception(),
            "rack_pdu_measurements": response([0xFFFF] * 6),
            "legacy_ups_id": response([0xFFFF]),
            "smt_status": response([0, 8194] + [0] * 21),
            "smt_measurements": response([0, 4845] + [0xFFFF] * 24),
        }
    )
    assert summary["detected_device_type"] == "smartconnect_ups"
    assert summary["decision"] == "definitive"


def test_smt_detection_requires_modbus_evidence() -> None:
    summary = collector._build_detection_summary(
        {
            "rack_pdu_capabilities": exception(),
            "rack_pdu_measurements": exception(),
            "legacy_ups_id": exception(),
            "smt_status": response([0] * 23),
            "smt_measurements": response([0] * 26),
        }
    )
    assert summary["detected_device_type"] == "smt_ups"


def test_pacing_preflight_controls_modbus_transport(monkeypatch) -> None:
    monkeypatch.setattr(
        collector,
        "_diagnose_modbus_pacing",
        lambda *args: {
            "ok": True,
            "effective_mode": "one_request_per_connection",
            "inter_request_delay_seconds": 3,
            "attempts": [],
        },
    )
    monkeypatch.setattr(
        collector, "_collect_modbus_block", lambda *args: {"parsed": {}}
    )
    monkeypatch.setattr(collector.time, "sleep", lambda *_: None)
    result = collector.collect_diagnostic_dump(
        "127.0.0.1",
        "public",
        502,
        1,
        snmp_availability="unavailable",
    )
    assert result["transport"]["effective_mode"] == "one_request_per_connection"
    assert result["transport"]["inter_request_delay_seconds"] == 3


def test_manual_request_delay_overrides_diagnosed_delay(monkeypatch) -> None:
    monkeypatch.setattr(
        collector,
        "_diagnose_modbus_pacing",
        lambda *args: {
            "ok": True,
            "effective_mode": "one_request_per_connection",
            "inter_request_delay_seconds": 0,
            "attempts": [],
        },
    )
    monkeypatch.setattr(
        collector, "_collect_modbus_block", lambda *args: {"parsed": {}}
    )
    monkeypatch.setattr(collector.time, "sleep", lambda *_: None)
    result = collector.collect_diagnostic_dump(
        "127.0.0.1",
        "public",
        502,
        1,
        snmp_availability="unavailable",
        request_delay_seconds=3,
    )
    assert result["transport"]["inter_request_delay_seconds"] == 3
    assert result["transport"]["request_delay_source"] == "manual"


def test_pacing_preflight_prefers_unpaced_session(monkeypatch) -> None:
    monkeypatch.setattr(
        collector.socket,
        "create_connection",
        lambda *args, **kwargs: nullcontext(object()),
    )
    monkeypatch.setattr(
        collector, "_modbus_read_holding_registers_on_connection", lambda *args: b""
    )
    result = collector._diagnose_modbus_pacing("127.0.0.1", 502, 1)
    assert result["effective_mode"] == "session"
    assert result["inter_request_delay_seconds"] == 0


def test_manual_delay_is_used_by_pacing_preflight(monkeypatch) -> None:
    monkeypatch.setattr(
        collector.socket,
        "create_connection",
        lambda *args, **kwargs: nullcontext(object()),
    )
    monkeypatch.setattr(
        collector, "_modbus_read_holding_registers_on_connection", lambda *args: b""
    )
    monkeypatch.setattr(collector.time, "sleep", lambda *_: None)
    result = collector._diagnose_modbus_pacing("127.0.0.1", 502, 1, 3)
    assert result["attempts"] == [
        {"mode": "session", "request_delay_seconds": 3, "ok": True}
    ]


def test_recv_exact_handles_fragmented_tcp_reads() -> None:
    class FragmentedSocket:
        def __init__(self) -> None:
            self.chunks = [b"ab", b"c", b"def"]

        def recv(self, _size: int) -> bytes:
            return self.chunks.pop(0)

    assert collector._recv_exact(FragmentedSocket(), 6) == b"abcdef"


def test_persistent_connection_failure_stops_remaining_blocks(monkeypatch) -> None:
    class Connection:
        def close(self) -> None:
            pass

    monkeypatch.setattr(
        collector,
        "_diagnose_modbus_pacing",
        lambda *args: {
            "ok": True,
            "effective_mode": "session",
            "inter_request_delay_seconds": 0,
            "attempts": [],
        },
    )
    monkeypatch.setattr(collector.socket, "create_connection", lambda *args, **kwargs: Connection())
    calls: list[object] = []
    monkeypatch.setattr(
        collector,
        "_collect_modbus_block",
        lambda *args: calls.append(args) or {"error": {"code": "read_failed"}},
    )
    result = collector.collect_diagnostic_dump(
        "127.0.0.1", "public", 502, 1, snmp_availability="unavailable"
    )
    assert len(calls) == 1
    assert result["modbus_skipped_reason"] == "persistent_connection_failed"


def test_invalid_delay_is_rejected() -> None:
    for delay in (float("nan"), -1):
        try:
            collector.collect_diagnostic_dump(
                "127.0.0.1", "public", 502, 1, request_delay_seconds=delay
            )
        except ValueError as err:
            assert "finite non-negative" in str(err)
        else:
            raise AssertionError(f"invalid delay {delay!r} was accepted")


def test_frequency_ignores_net_snmp_type_digits() -> None:
    assert collector._parse_snmp_frequency_hz("Gauge32: 50") == 50
    assert collector._parse_snmp_frequency_hz("INTEGER: 500") == 50


def test_human_report_summarizes_diagnostic_outcome() -> None:
    report = collector.format_human_report(
        {
            "snmp": {"sysName": {"value": "STRING: Garage"}},
            "modbus_pacing": {
                "ok": True,
                "effective_mode": "session",
                "inter_request_delay_seconds": 3,
            },
            "detection": {"detected_device_type": "smt_ups", "decision": "definitive"},
            "modbus": {"block": {"parsed": {}}},
            "external_probe_tests": {"detect": {"ok": True}},
        }
    )
    assert "Modbus pacing: session, 3s between requests" in report
    assert "Device detection: smt_ups (definitive)" in report


def test_snmp_failure_stops_all_follow_up_requests(monkeypatch) -> None:
    calls: list[str] = []

    def fail_once(_host: str, _community: str, oid: str) -> None:
        calls.append(oid)
        return None

    monkeypatch.setattr(collector, "_snmpget_value", fail_once)
    monkeypatch.setattr(
        collector,
        "_diagnose_modbus_pacing",
        lambda *args: {"ok": False, "attempts": []},
    )
    monkeypatch.setattr(
        collector, "_collect_modbus_block", lambda *args: {"parsed": {}}
    )
    result = collector.collect_diagnostic_dump(
        "host", "public", 502, 1, full_snmp=True
    )
    assert calls == [next(iter(collector.SNMP_OIDS.values()))]
    assert result["snmp"]["sysName"]["error"]["code"] == "snmp_missing"
    assert result["snmp_full"] == {"skipped_reason": "snmp_failure"}
    assert result["external_probe_tests"] == {"skipped_reason": "snmp_failure"}
