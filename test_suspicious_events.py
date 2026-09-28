
import json
from pathlib import Path


RESULTS_DIR = Path("analysis_results")


def load_json_file(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def main():

    possible_files = [
        RESULTS_DIR / "complete.json",
        RESULTS_DIR / "MEM-001_complete.json",
        RESULTS_DIR / "timeline.json",
        RESULTS_DIR / "MEM-001_timeline.json"
    ]

    result_file = None

    for file_path in possible_files:
        if file_path.exists():
            result_file = file_path
            break

    if result_file is None:
        print("No analysis result file was found.")
        print("Check the analysis_results folder.")
        return

    print(f"Reading: {result_file}")

    data = load_json_file(result_file)

    if isinstance(data, dict):
        events = data.get("analyzed_events", [])

        if not events:
            events = data.get("timeline", [])

    elif isinstance(data, list):
        events = data

    else:
        events = []

    print(f"Total events loaded: {len(events)}")

    suspicious_count = 0

    for index, event in enumerate(events, start=1):

        rule_score = event.get("rule_score", 0)
        indicators = event.get("indicators", [])
        yara_matches = event.get("yara_matches", [])
        risk_level = event.get("risk_level", "UNKNOWN")

        if rule_score > 0 or indicators or yara_matches:

            suspicious_count += 1

            print("\n" + "=" * 70)
            print(f"Suspicious Event: {suspicious_count}")
            print("=" * 70)

            print(f"Event Type: {event.get('event_type')}")
            print(f"Source: {event.get('source')}")
            print(f"Severity: {event.get('severity')}")
            print(f"Risk Level: {risk_level}")
            print(f"Rule Score: {rule_score}")
            print(f"Indicators: {indicators}")
            print(f"YARA Matches: {yara_matches}")

            evidence = event.get("evidence", {})

            if isinstance(evidence, dict):
                raw_data = evidence.get("raw_data", "")
                print("\nRaw Evidence:")
                print(raw_data)

    print("\n" + "=" * 70)
    print(f"Suspicious events displayed: {suspicious_count}")
    print("=" * 70)


if __name__ == "__main__":
    main()