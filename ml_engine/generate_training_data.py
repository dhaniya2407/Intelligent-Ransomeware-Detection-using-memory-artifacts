import csv
import os
import random


# ============================================================
# DATASET LOCATION
# ============================================================

DATASET_FILE = os.path.join(
    os.path.dirname(__file__),
    "dataset.csv"
)


# ============================================================
# CSV HEADER
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
    "suspicious_event_ratio",
    "label"
]


# ============================================================
# CREATE SAMPLE
# ============================================================

def create_sample(label):

    if label == 0:
        # Normal system activity

        total_events = random.randint(50, 300)

        suspicious_events = random.randint(0, 2)

        return [
            total_events,
            random.randint(20, 150),
            random.randint(10, 100),
            random.randint(0, 20),
            random.randint(0, 20),
            random.randint(5, 50),
            suspicious_events,
            0,
            random.randint(0, 1),
            0,
            0,
            0,
            random.randint(0, 10),
            random.randint(0, 10),
            random.randint(0, 2),
            0,
            0,
            suspicious_events / total_events,
            label
        ]

    elif label == 1:
        # Suspicious activity

        total_events = random.randint(100, 500)

        suspicious_events = random.randint(3, 20)

        return [
            total_events,
            random.randint(50, 250),
            random.randint(20, 150),
            random.randint(0, 50),
            random.randint(5, 50),
            random.randint(10, 80),
            suspicious_events,
            random.randint(0, 3),
            random.randint(1, 8),
            random.randint(1, 8),
            random.randint(0, 3),
            random.randint(1, 5),
            random.randint(10, 50),
            random.randint(10, 50),
            random.randint(1, 8),
            random.randint(0, 2),
            random.randint(1, 5),
            suspicious_events / total_events,
            label
        ]

    else:
        # Ransomware-like forensic activity

        total_events = random.randint(300, 1000)

        suspicious_events = random.randint(20, 100)

        return [
            total_events,
            random.randint(100, 500),
            random.randint(50, 300),
            random.randint(10, 100),
            random.randint(20, 150),
            random.randint(20, 150),
            suspicious_events,
            random.randint(3, 15),
            random.randint(5, 20),
            random.randint(5, 30),
            random.randint(2, 15),
            random.randint(5, 20),
            random.randint(50, 200),
            random.randint(30, 100),
            random.randint(5, 20),
            random.randint(1, 10),
            random.randint(2, 10),
            suspicious_events / total_events,
            label
        ]


# ============================================================
# GENERATE DATASET
# ============================================================

def generate_dataset():

    samples = []

    # 50 Normal
    for _ in range(50):
        samples.append(create_sample(0))

    # 50 Suspicious
    for _ in range(50):
        samples.append(create_sample(1))

    # 50 Ransomware
    for _ in range(50):
        samples.append(create_sample(2))

    random.shuffle(samples)

    with open(
        DATASET_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(FEATURE_NAMES)

        writer.writerows(samples)

    print("==========================================")
    print("     TRAINING DATASET CREATED")
    print("==========================================")
    print()
    print("Normal samples     : 50")
    print("Suspicious samples : 50")
    print("Ransomware samples : 50")
    print()
    print("Total samples      : 150")
    print()
    print("Dataset:")
    print(DATASET_FILE)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    generate_dataset()