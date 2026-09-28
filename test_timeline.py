from forensic_engine.forensic_parser import parse_all_results
from forensic_engine.timeline_engine import build_timeline


print("======================================")
print("FORENSIRANSOM AI")
print("FORENSIC TIMELINE ENGINE")
print("======================================")


print("\nReading forensic analysis results...")

events = parse_all_results()

print("Parsed events:", len(events))


print("\nBuilding investigation timeline...")

timeline = build_timeline(events)


print("Timeline events:", len(timeline))


for index, event in enumerate(timeline[:30], start=1):

    print("\n======================================")
    print("EVENT", index)
    print("======================================")

    print("TYPE     :", event["event_type"])
    print("WHAT     :", event["what"])
    print("WHY      :", event["why"])
    print("SOURCE   :", event["source"])
    print("SEVERITY :", event["severity"])

    print("EVIDENCE :")
    print(event["evidence"])


print("\n======================================")
print("TIMELINE GENERATION COMPLETED")
print("======================================")