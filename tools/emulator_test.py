"""
Run every detection's real KQL against synthetic log rows on the Kusto emulator.

  docker run -d -e ACCEPT_EULA=Y -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
  python tools/emulator_test.py                    # runs against http://localhost:8080
  python tools/emulator_test.py --print-kql NAME   # show the exact query sent for one case

Each detection has a case file in tests/emulator/cases/ with at least one case that must
alert ("hit") and one that must not ("miss"). For each case the runner prepends a typed
`let <Table> = datatable(...) [...]` for every table the detection reads, then the
detection's query, unchanged. The `let` shadows the table name, so the query text that
runs is exactly the text deployed to Sentinel.

Time values like "-25m" are relative to the moment the test runs, because the detections
filter with ago().
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests" / "emulator" / "cases"
SCHEMAS = yaml.safe_load((ROOT / "tests" / "emulator" / "schemas.yaml").read_text())
REL_TIME = re.compile(r"^-(\d+)([smhd])$")
UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


# --------------------------------------------------------------------------- literals
def kql_string(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)          # "..." with \" and \\ escapes, valid KQL


def resolve(value, ctype: str, now: datetime):
    """Turn a YAML value into a KQL literal of the column's type."""
    if value is None:
        return {"string": '""'}.get(ctype, f"{ctype}(null)")
    if ctype == "datetime":
        m = REL_TIME.match(str(value))
        t = now - timedelta(**{UNITS[m[2]]: int(m[1])}) if m else datetime.fromisoformat(str(value))
        return f"datetime({t.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
    if ctype == "dynamic":
        return f"dynamic({compact(expand_json(value))})"
    if ctype == "string":
        # logs store JSON-in-a-string compactly (no spaces), e.g. OfficeActivity.Parameters
        return kql_string(compact(expand_json(value)) if isinstance(value, (dict, list)) else str(value))
    if ctype == "bool":
        return "true" if value else "false"
    if ctype in ("long", "int", "real"):
        return str(value)
    raise ValueError(f"unsupported column type {ctype}")


def compact(v) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def expand_json(v):
    """Keys ending in __json hold an object that the real log stores as a JSON-encoded string."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k.endswith("__json"):
                out[k[:-6]] = compact(expand_json(x))
            else:
                out[k] = expand_json(x)
        return out
    if isinstance(v, list):
        return [expand_json(x) for x in v]
    return v


def expand_rows(rows: list[dict]) -> list[dict]:
    """A row with _repeat: N becomes N rows; '{i}' in any string value becomes 0..N-1."""
    out = []
    for r in rows:
        n = int(r.get("_repeat", 1))
        for i in range(n):
            out.append({k: (v.replace("{i}", str(i)) if isinstance(v, str) else v)
                        for k, v in r.items() if k != "_repeat"})
    return out


def datatable(name: str, rows: list[dict], now: datetime) -> str:
    schema = SCHEMAS[name]
    unknown = {k for r in rows for k in r} - set(schema)
    if unknown:
        raise ValueError(f"{name}: columns not in schema: {sorted(unknown)}")
    cols = ", ".join(f"{c}:{t}" for c, t in schema.items())
    values = ",\n    ".join(", ".join(resolve(r.get(c), t, now) for c, t in schema.items()) for r in rows)
    return f"let {name} = datatable({cols}) [\n    {values}\n];"


def build_query(detection: dict, case: dict, now: datetime) -> str:
    tables = case.get("tables", {})
    extra = set(tables) - set(detection["data_sources"])
    if extra:
        raise ValueError(f"case defines tables the detection does not read: {sorted(extra)}")
    lets = [datatable(t, expand_rows(tables.get(t, [])), now) for t in detection["data_sources"]]
    return "\n".join(lets) + "\n" + detection["query"].strip()


def load_cases():
    out = []
    for f in sorted(CASES.glob("*.yaml")):
        spec = yaml.safe_load(f.read_text())
        det = yaml.safe_load((ROOT / "detections" / spec["detection"]).read_text())
        out.append((f.stem, det, spec["cases"]))
    return out


# --------------------------------------------------------------------------- emulator
def kusto(url: str, csl: str, mgmt: bool = False) -> dict:
    body = json.dumps({"db": "NetDefaultDB", "csl": csl}).encode()
    req = urllib.request.Request(f"{url}/v1/rest/{'mgmt' if mgmt else 'query'}", data=body,
                                 headers={"Content-Type": "application/json; charset=utf-8"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def wait_ready(url: str, seconds: int) -> None:
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        try:
            kusto(url, ".show version", mgmt=True)
            return
        except Exception as e:  # noqa: BLE001 - any failure means "not up yet"
            last = e
            time.sleep(5)
    raise SystemExit(f"Kusto emulator not ready after {seconds}s: {last}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--wait", type=int, default=300, help="seconds to wait for the emulator")
    ap.add_argument("--print-kql", metavar="CASE", help="print the query for a case name and exit")
    args = ap.parse_args()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    suites = load_cases()
    if args.print_kql:
        for _, det, cases in suites:
            for c in cases:
                if c["name"] == args.print_kql:
                    print(build_query(det, c, now))
                    return 0
        print(f"no case named {args.print_kql!r}")
        return 1
    wait_ready(args.url, args.wait)
    failures, lines = [], []
    for stem, det, cases in suites:
        for c in cases:
            q = build_query(det, c, now)
            try:
                res = kusto(args.url, q)
                rows = len(res["Tables"][0]["Rows"])
                ok = (rows > 0) == (c["expect"] == "hit")
                detail = f"{rows} row(s)"
            except urllib.error.HTTPError as e:
                ok, detail = False, f"query error: {e.read().decode(errors='replace')[:400]}"
            lines.append(f"{'PASS' if ok else 'FAIL'}  {stem:32} {c['expect']:4}  {c['name']}  ({detail})")
            if not ok:
                failures.append(lines[-1])
    print("\n".join(lines))
    total = sum(len(c) for _, _, c in suites)
    print(f"\n{total - len(failures)}/{total} emulator cases passed across {len(suites)} detections")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
