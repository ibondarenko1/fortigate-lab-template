"""Exercise the packaged worksheet over its published HTTP port."""

import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen


SCENARIOS = Path(__file__).resolve().parents[1] / "training" / "scenarios"


def request_json(base, endpoint, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(base + endpoint, data=data, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def check(port):
    base = f"http://127.0.0.1:{port}/training/"
    with urlopen(base, timeout=5) as page:
        if page.status != 200 or b"grade-config" not in page.read():
            raise ValueError("Worksheet HTML did not contain the configuration editor")
    exercises = request_json(base, "api/catalog")["exercises"]
    expected_ids = sorted(path.parent.name for path in SCENARIOS.glob("*/reference.conf"))
    if not expected_ids or sorted(item["id"] for item in exercises) != expected_ids:
        raise ValueError("The packaged catalog differs from the scenario directories")
    for item in exercises:
        exercise_id = item["id"]
        fixed = (SCENARIOS / exercise_id / "reference.conf").read_text(encoding="utf-8")
        args = {"exercise_id": exercise_id}
        original = request_json(base, "api/grade", {**args, "config": item["config"]})
        repaired = request_json(base, "api/grade", {**args, "config": fixed})
        if original["pass"] or not repaired["pass"]:
            raise ValueError(f"{exercise_id}: starter/reference verdicts are incorrect")
        diff = request_json(base, "api/compare", {**args, "before": item["config"], "after": fixed})
        if diff["errors"] or not diff["flows"]:
            raise ValueError(f"{exercise_id}: comparison did not return flow decisions")
    custom = (SCENARIOS / "custom-tcp-port" / "reference.conf").read_text(encoding="utf-8")
    widened = custom.replace("set tcp-portrange 8081", "set tcp-portrange 8081-65535")
    args = {"exercise_id": "custom-tcp-port"}
    if request_json(base, "api/grade", {**args, "config": widened})["pass"]:
        raise ValueError("The packaged worksheet accepted a widened port range")
    diff = request_json(base, "api/compare", {**args, "before": custom, "after": widened})
    if not any(row["destination_port"] == 8082 and row["changed"] and
               row["after"]["outcome"] == "allowed" for row in diff["flows"]):
        raise ValueError("The comparison missed the newly allowed connection on TCP/8082")
    print(f"HTTP worksheet passed {len(exercises)} starter/reference pairs and the TCP/8082 change check")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18846)
    check(parser.parse_args().port)
