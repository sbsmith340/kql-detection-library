"""Offline checks on the emulator test cases (the queries themselves run in the emulator workflow)."""
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build  # noqa: E402
import emulator_test as et  # noqa: E402

SUITES = et.load_cases()
NOW = datetime(2026, 10, 1, 12, 0, 0)


def test_every_detection_has_hit_and_miss_cases():
    covered = {det["id"]: {c["expect"] for c in cases} for _, det, cases in SUITES}
    for path, det in build.load_all():
        assert covered.get(det["id"]) == {"hit", "miss"}, f"{path.name} needs at least one hit and one miss case"


def test_every_case_builds_a_query():
    for _, det, cases in SUITES:
        for c in cases:
            q = et.build_query(det, c, NOW)
            assert q.endswith(det["query"].strip())          # the detection text is sent unchanged
            for table in det["data_sources"]:
                assert f"let {table} = datatable(" in q


def test_relative_times_and_literals():
    assert et.resolve("-90m", "datetime", NOW) == "datetime(2026-10-01T10:30:00.000000Z)"
    assert et.resolve(None, "dynamic", NOW) == "dynamic(null)"
    assert et.resolve('say "hi"', "string", NOW) == '"say \\"hi\\""'
    assert et.resolve([{"Name": "ForwardTo", "Value": "x@y.example"}], "string", NOW) == \
        '"[{\\"Name\\":\\"ForwardTo\\",\\"Value\\":\\"x@y.example\\"}]"'
    assert len(et.expand_rows([{"a": "u{i}", "_repeat": 3}])) == 3


def test_unknown_column_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        et.datatable("SigninLogs", [{"NotAColumn": 1}], NOW)
