from forensic_engine.forensic_parser import parse_all_results
from forensic_engine.timeline_engine import build_timeline
from forensic_engine.rule_engine import analyze_timeline
from forensic_engine.correlation_engine import correlate_events


print("======================================")
print("FORENSIRANSOM AI")
print("EVIDENCE CORRELATION ENGINE")
print("======================================")


# Step 1
print("\n[1] Reading forensic results...")

events = parse_all_results()

print("Parsed events:", len(events))


# Step 2
print("\n[2] Building timeline...")

timeline = build_timeline(events)

print("Timeline events:", len(timeline))


# Step 3
print("\n[3] Running rule engine...")

analyzed_events = analyze_timeline(timeline)

print(
    "Analyzed events:",
    len(analyzed_events)
)


# Step 4
print("\n[4] Correlating evidence...")

correlations = correlate_events(
    analyzed_events
)

print(
    "Correlations found:",
    len(correlations)
)


# Step 5
print("\n======================================")
print("CORRELATION RESULTS")
print("======================================")


for index, correlation in enumerate(
    correlations[:20],
    start=1
):

    print("\n--------------------------------------")
    print("CORRELATION:", index)

    print(
        "TYPE:",
        correlation["correlation_type"]
    )

    print(
        "DESCRIPTION:",
        correlation["description"]
    )

    print(
        "SEVERITY:",
        correlation["severity"]
    )


print("\n======================================")
print("CORRELATION TEST COMPLETED")
print("======================================")