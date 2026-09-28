from forensic_engine.forensic_parser import parse_all_results
from forensic_engine.yara_engine import scan_text


def main():

    print("Starting YARA forensic integration test...")

    events = parse_all_results()

    total_events = len(events)
    yara_matches = []

    print(f"Total forensic events: {total_events}")

    for event in events:

        evidence = event.get(
            "evidence",
            {}
        )

        raw_data = evidence.get(
            "raw_data",
            ""
        )

        if not raw_data:
            continue

        matches = scan_text(raw_data)

        if matches:

            yara_matches.append({
                "event_type": event.get(
                    "event_type",
                    "UNKNOWN"
                ),
                "source": event.get(
                    "source",
                    "UNKNOWN"
                ),
                "matches": matches
            })

    print()
    print("YARA MATCHED EVENTS:", len(yara_matches))

    for index, result in enumerate(
        yara_matches[:10],
        start=1
    ):

        print()
        print(f"Match {index}")
        print("Event Type:", result["event_type"])
        print("Source:", result["source"])
        print("Rules:", result["matches"])

    print()
    print("YARA integration test completed.")


if __name__ == "__main__":
    main()