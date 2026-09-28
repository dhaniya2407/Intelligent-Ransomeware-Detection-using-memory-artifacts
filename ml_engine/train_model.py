import os

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

import joblib


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(__file__)

DATASET_FILE = os.path.join(
    BASE_DIR,
    "dataset.csv"
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "forensic_ml_model.pkl"
)


# ============================================================
# LABEL INFORMATION
# ============================================================

LABEL_NAMES = {
    0: "Normal",
    1: "Suspicious",
    2: "Ransomware"
}


# ============================================================
# LOAD DATASET
# ============================================================

print("==========================================")
print("     FORENSIRANSOM AI - ML TRAINING")
print("==========================================")

print()
print("Loading dataset...")

data = pd.read_csv(DATASET_FILE)

print(
    "Total samples:",
    len(data)
)


# ============================================================
# CHECK DATASET
# ============================================================

if "label" not in data.columns:

    raise ValueError(
        "label column not found in dataset.csv"
    )


print()
print("Dataset loaded successfully.")


# ============================================================
# SEPARATE FEATURES AND LABEL
# ============================================================

X = data.drop(
    columns=["label"]
)

y = data["label"]


print()
print("Number of features:", X.shape[1])
print("Number of samples:", X.shape[0])


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print()
print("Training samples:", len(X_train))
print("Testing samples :", len(X_test))


# ============================================================
# CREATE RANDOM FOREST MODEL
# ============================================================

print()
print("Training Random Forest model...")


model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


model.fit(
    X_train,
    y_train
)


print("Model training completed.")


# ============================================================
# TEST MODEL
# ============================================================

predictions = model.predict(
    X_test
)


accuracy = accuracy_score(
    y_test,
    predictions
)


print()
print("==========================================")
print("             MODEL RESULTS")
print("==========================================")

print()
print(
    f"Accuracy: {accuracy * 100:.2f}%"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print()
print("Classification Report:")
print()

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            LABEL_NAMES[0],
            LABEL_NAMES[1],
            LABEL_NAMES[2]
        ],
        zero_division=0
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(
    model,
    MODEL_FILE
)


print()
print("==========================================")
print("ML MODEL SAVED SUCCESSFULLY")
print("==========================================")

print()
print("Model file:")
print(MODEL_FILE)

print()
print("Labels:")

for label, name in LABEL_NAMES.items():

    print(
        f"{label} = {name}"
    )

print()
print("Training completed successfully.")