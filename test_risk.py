from forensic_engine.forensic_parser import parse_all_results
from forensic_engine.timeline_engine import build_timeline
from forensic_engine.rule_engine import analyze_timeline
from forensic_engine.correlation_engine import correlate_events
from forensic_engine.feature_engine import extract_features
from forensic_engine.risk_engine import calculate_risk_score


print("======================================")
print("FORENSIRANSOM AI")
print("FORENSIC RISK ENGINE")
print("======================================")


# ---------------------------------
# 1. Parse forensic data
# ---------------------------------

print("\n[1] Parsing forensic results...")

events = parse_all_results()

print("Events:", len(events))


# ---------------------------------
# 2. Build timeline
# ---------------------------------

print("\n[2] Building timeline...")

timeline = build_timeline(events)

print("Timeline events:", len(timeline))


# ---------------------------------
# 3. Rule engine
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
# 4. Correlation
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
# 5. Feature extraction
# ---------------------------------

print("\n[5] Extracting features...")

features = extract_features(
    analyzed_events,
    correlations
)


# ---------------------------------
# 6. Risk scoring
# ---------------------------------

print("\n[6] Calculating risk...")

risk = calculate_risk_score(
    features
)


# ---------------------------------
# 7. Display result
# ---------------------------------

print("\n======================================")
print("FORENSIC RISK ASSESSMENT")
print("======================================")

print(
    "Risk Score :",
    risk["risk_score"],
    "/ 100"
)

print(
    "Risk Level :",
    risk["risk_level"]
)


print("\nReasons:")

for reason in risk["reasons"]:

    print(
        " -",
        reason
    )


print("\n======================================")
print("RISK ENGINE TEST COMPLETED")
print("======================================")