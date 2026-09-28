import os

import pandas as pd
import joblib


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(__file__)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "forensic_ml_model.pkl"
)


# ============================================================
# FEATURE ORDER
# Must match the training dataset
# ============================================================

FEATURE_NAMES = [

    "total_events",

    "process_events",

    "process_scan_events",

    "network_events",

    "command_events",

    "relationship_events",

    "suspicious_events",

    "high_risk_events",

    "medium_risk_events",

    "powershell_events",

    "encoded_command_events",

    "suspicious_tool_events",

    "total_rule_score",

    "maximum_rule_score",

    "correlation_count",

    "high_severity_correlations",

    "medium_severity_correlations",

    "suspicious_event_ratio"

]


# ============================================================
# LABEL NAMES
# ============================================================

LABEL_NAMES = {

    0: "Normal",

    1: "Suspicious",

    2: "Ransomware"

}


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    if not os.path.exists(MODEL_FILE):

        raise FileNotFoundError(
            "ML model not found. "
            "Run train_model.py first."
        )

    return joblib.load(
        MODEL_FILE
    )


# ============================================================
# PREDICT FORENSIC RESULT
# ============================================================

def predict(features):

    model = load_model()

    # Create feature row
    feature_row = {}

    for feature_name in FEATURE_NAMES:

        feature_row[feature_name] = features.get(
            feature_name,
            0
        )

    # Convert to DataFrame
    input_data = pd.DataFrame(
        [feature_row],
        columns=FEATURE_NAMES
    )

    # Prediction
    prediction = model.predict(
        input_data
    )[0]

    # Probability
    probabilities = model.predict_proba(
        input_data
    )[0]

    # Convert probabilities into readable format
    probability_result = {}

    for index, probability in enumerate(probabilities):

        probability_result[
            LABEL_NAMES.get(
                index,
                str(index)
            )
        ] = round(
            float(probability) * 100,
            2
        )

    return {

        "prediction":
            int(prediction),

        "classification":
            LABEL_NAMES.get(
                int(prediction),
                "Unknown"
            ),

        "probabilities":
            probability_result
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("==========================================")
    print("       FORENSIRANSOM AI - ML PREDICTOR")
    print("==========================================")

    # Test feature sample
    test_features = {

        "total_events": 500,

        "process_events": 250,

        "process_scan_events": 100,

        "network_events": 20,

        "command_events": 40,

        "relationship_events": 50,

        "suspicious_events": 20,

        "high_risk_events": 5,

        "medium_risk_events": 8,

        "powershell_events": 10,

        "encoded_command_events": 5,

        "suspicious_tool_events": 8,

        "total_rule_score": 100,

        "maximum_rule_score": 50,

        "correlation_count": 10,

        "high_severity_correlations": 3,

        "medium_severity_correlations": 4,

        "suspicious_event_ratio": 0.04

    }

    result = predict(
        test_features
    )

    print()
    print("Prediction:")
    print(
        result["classification"]
    )

    print()
    print("Probabilities:")

    for label, probability in result[
        "probabilities"
    ].items():

        print(
            f"{label}: {probability}%"
        )

    print()
    print("Prediction completed.")