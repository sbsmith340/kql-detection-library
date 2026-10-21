import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import build  # noqa: E402

ITEMS = build.load_all()


def test_has_detections():
    assert len(ITEMS) >= 12


def test_all_detections_valid():
    errors = [e for p, d in ITEMS for e in build.validate(p, d)]
    assert errors == []


def test_ids_unique():
    ids = [d["id"] for _, d in ITEMS]
    assert len(ids) == len(set(ids))


def test_validator_catches_missing_field():
    p, d = ITEMS[0]
    bad = copy.deepcopy(d)
    del bad["tuning"]
    assert any("missing 'tuning'" in e for e in build.validate(p, bad))


def test_validator_catches_bad_technique_and_tactic():
    p, d = ITEMS[0]
    bad = copy.deepcopy(d)
    bad["techniques"] = ["1110"]
    bad["tactics"] = ["Credential Access"]
    errs = build.validate(p, bad)
    assert any("technique" in e for e in errs) and any("unknown tactic" in e for e in errs)


def test_validator_catches_entity_column_not_in_query():
    p, d = ITEMS[0]
    bad = copy.deepcopy(d)
    bad["entity_mappings"] = [{"entityType": "Host", "fieldMappings": [{"identifier": "HostName", "columnName": "NoSuchColumn"}]}]
    assert any("NoSuchColumn" in e for e in build.validate(p, bad))


def test_validator_catches_period_gap():
    p, d = ITEMS[0]
    bad = copy.deepcopy(d)
    bad["query_frequency"], bad["query_period"] = "P1D", "PT1H"
    assert any("gaps" in e for e in build.validate(p, bad))


def test_arm_template_shape():
    arm = build.build_arm(ITEMS)
    assert len(arm["resources"]) == len(ITEMS)
    r = arm["resources"][0]
    assert r["kind"] == "Scheduled"
    assert r["properties"]["enabled"] == "[parameters('enableRules')]"
    assert all("." not in t for res in arm["resources"] for t in res["properties"]["techniques"])


def test_generated_files_are_current():
    assert build.INDEX.read_text() == build.build_index(ITEMS)
