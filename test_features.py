from forensic_engine.forensic_parser import parse_all_results
from forensic_engine.timeline_engine import build_timeline
from forensic_engine.rule_engine import analyze_timeline
from forensic_engine.correlation_engine import correlate_events
from forensic_engine.feature_engine import extract_features


print("======================================")
print("FORENSIRANSOM AI")
print("FEATURE EXTRACTION ENGINE")
print("======================================")


# ---------------------------------
# 1. Parse forensic results
# ---------------------------------

print("\n[1] Parsing forensic results...")

events = parse_all_results()

print("Parsed events:", len(events))


# ---------------------------------
# 2. Build timeline
# ---------------------------------

print("\n[2] Building timeline...")

timeline = build_timeline(events)

print("Timeline events:", len(timeline))


# ---------------------------------
# 3. Run rules
# ---------------------------------

print("\n[3] Running rule engine...")

analyzed_events = analyze_timeline(
    timeline
)

print(
    "Analyzed events:",
    len(analyzed_events)
)


# ---------------------------------
# 4. Correlate evidence
# ---------------------------------

print("\n[4] Correlating evidence...")

correlations = correlate_events(
    analyzed_events
)

print(
    "Correlations:",
    len(correlations)
)


# ---------------------------------
# 5. Extract features
# ---------------------------------

print("\n[5] Extracting ML features...")

features = extract_features(
    analyzed_events,
    correlations
)


# ---------------------------------
# 6. Display features
# ---------------------------------

print("\n======================================")
print("EXTRACTED FORENSIC FEATURES")
print("======================================")


for name, value in features.items():

    print(
        f"{name:35} : {value}"
    )


print("\n======================================")
print("FEATURE EXTRACTION COMPLETED")
print("======================================")