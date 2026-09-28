from forensic_engine.forensic_parser import parse_all_results
from forensic_engine.timeline_engine import build_timeline
from forensic_engine.rule_engine import analyze_timeline


print("======================================")
print("FORENSIRANSOM AI")
print("SUSPICIOUS BEHAVIOR RULE ENGINE")
print("======================================")


print("\nReading forensic results...")

events = parse_all_results()

print("Parsed events:", len(events))


print("\nBuilding timeline...")

timeline = build_timeline(events)

print("Timeline events:", len(timeline))


print("\nRunning suspicious behavior rules...")

analyzed_events = analyze_timeline(timeline)


high = 0
medium = 0
low = 0


for event in analyzed_events:

    if event["risk_level"] == "HIGH":
        high += 1

    elif event["risk_level"] == "MEDIUM":
        medium += 1

    else:
        low += 1


print("\n======================================")
print("RULE ENGINE SUMMARY")
print("======================================")

print("HIGH RISK  :", high)
print("MEDIUM RISK:", medium)
print("LOW RISK   :", low)


print("\n======================================")
print("SUSPICIOUS EVENTS")
print("======================================")


count = 0

for event in analyzed_events:

    if event["rule_score"] > 0:

        count += 1

        print("\n--------------------------------------")

        print("TYPE       :", event["event_type"])
        print("SOURCE     :", event["source"])
        print("RISK LEVEL :", event["risk_level"])
        print("RULE SCORE :", event["rule_score"])

        print("INDICATORS:")

        for indicator in event["indicators"]:
            print(" -", indicator)

        print("EVIDENCE:")
        print(event["evidence"])

        if count >= 20:
            break


print("\n======================================")
print("RULE ENGINE TEST COMPLETED")
print("======================================")