import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_evidence_information(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    return {
        "filename": path.name,
        "file_size": path.stat().st_size,
        "sha256": calculate_sha256(path),
        "file_type": path.suffix
    }