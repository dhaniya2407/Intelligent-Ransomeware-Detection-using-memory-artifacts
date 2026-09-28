import csv
import os


# ============================================================
# ML DATASET CONFIGURATION
# ============================================================

DATASET_FILE = os.path.join(
    os.path.dirname(__file__),
    "dataset.csv"
)


# ============================================================
# FEATURE NAMES
# Must match feature_engine.py
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
# LABELS
# ============================================================

LABELS = {
    0: "Normal",
    1: "Suspicious",
    2: "Ransomware"
}


# ============================================================
# CREATE DATASET
# ============================================================

def create_dataset():

    header = FEATURE_NAMES + ["label"]

    if not os.path.exists(DATASET_FILE):

        with open(
            DATASET_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(header)

        print("dataset.csv created successfully.")

    else:

        print("dataset.csv already exists.")


# ============================================================
# ADD FORENSIC FEATURES
# ============================================================

def add_sample(features, label):

    if label not in LABELS:

        raise ValueError(
            "Invalid label. Use 0, 1, or 2."
        )

    row = []

    for feature_name in FEATURE_NAMES:

        value = features.get(
            feature_name,
            0
        )

        row.append(value)

    row.append(label)

    with open(
        DATASET_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(row)

    print("--------------------------------------------------")
    print("ML sample added successfully")
    print("Label:", label, "-", LABELS[label])
    print("Dataset:", DATASET_FILE)
    print("--------------------------------------------------")


# ============================================================
# DISPLAY FEATURES
# ============================================================

def display_features(features):

    print()
    print("Extracted Forensic Features")
    print("============================")

    for feature_name in FEATURE_NAMES:

        value = features.get(
            feature_name,
            0
        )

        print(
            f"{feature_name}: {value}"
        )

    print()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    create_dataset()

    print()
    print("==========================================")
    print("     FORENSIRANSOM AI - ML ENGINE")
    print("==========================================")

    print()
    print("Dataset file:")
    print(DATASET_FILE)

    print()
    print("Available labels:")

    for number, name in LABELS.items():

        print(
            f"{number} = {name}"
        )

    print()
    print("ML dataset structure is ready.")
    print()
    print("Next:")
    print("Real forensic features will be connected")
    print("to this dataset from the analysis pipeline.")