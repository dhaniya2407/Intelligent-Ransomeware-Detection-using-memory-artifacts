import os
import yara
from typing import List, Dict, Any, Optional

# ============================================================
# PROJECT ROOT & DYNAMIC YARA RULES PATH
# ============================================================

def resolve_project_root():
    """
    Traverse upward to find the real project root directory containing both backend and frontend.
    """
    d = os.path.dirname(os.path.abspath(__file__))
    while d and os.path.dirname(d) != d:
        if os.path.exists(os.path.join(d, "frontend")) and os.path.exists(os.path.join(d, "backend")):
            return d
        if os.path.exists(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.basename(parent) == "backend":
        return os.path.dirname(parent)
    return parent


PROJECT_ROOT = resolve_project_root()

def get_yara_rules_path():
    """
    Locates the ransomware YARA rules file across known relative and environment paths.
    """
    candidates = [
        os.environ.get("YARA_RULES_PATH"),
        os.path.join(PROJECT_ROOT, "yara_rules", "ransomware_rules.yar"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "yara_rules", "ransomware_rules.yar"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "yara_rules", "ransomware_rules.yar"),
        os.path.join(os.getcwd(), "yara_rules", "ransomware_rules.yar"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return os.path.join(PROJECT_ROOT, "yara_rules", "ransomware_rules.yar")

YARA_RULES_PATH = get_yara_rules_path()

_COMPILED_RULES = None


def load_yara_rules():
    """
    Load and compile YARA rules from the project rules directory.
    Uses memory caching so compiled rules are reused across events.
    """
    global _COMPILED_RULES
    if _COMPILED_RULES is not None:
        return _COMPILED_RULES

    rules_path = get_yara_rules_path()
    if not os.path.exists(rules_path):
        raise FileNotFoundError(
            f"YARA rules file not found: {rules_path}"
        )

    _COMPILED_RULES = yara.compile(
        filepath=rules_path
    )
    return _COMPILED_RULES


def convert_matches(matches):
    """
    Convert YARA results into a consistent ForensiRansom AI result format.
    Distinguishes rule matches from confirmed infections.
    """
    results = []

    if isinstance(matches, list):
        for match in matches:
            if isinstance(match, str):
                results.append({
                    "rule": match,
                    "description": "YARA signature pattern matched.",
                    "author": "ForensiRansom AI",
                    "severity": "LOW",
                    "mitre_technique": None,
                    "is_confirmed_ransomware": False,
                    "matched": True
                })
            else:
                metadata = getattr(match, "meta", {})
                results.append({
                    "rule": getattr(match, "rule", "Unknown"),
                    "description": metadata.get(
                        "description",
                        "Suspicious pattern detected."
                    ),
                    "author": metadata.get(
                        "author",
                        "ForensiRansom AI"
                    ),
                    "severity": metadata.get(
                        "severity",
                        "LOW"
                    ),
                    "mitre_technique": metadata.get(
                        "mitre_technique",
                        None
                    ),
                    "is_confirmed_ransomware": False,
                    "matched": True
                })
        return results

    if isinstance(matches, dict):
        for category, match_items in matches.items():
            if not isinstance(match_items, list):
                continue
            for match in match_items:
                if isinstance(match, dict):
                    metadata = match.get("meta", {})
                    results.append({
                        "rule": match.get("rule", "Unknown"),
                        "description": metadata.get(
                            "description",
                            "YARA rule matched."
                        ),
                        "author": metadata.get(
                            "author",
                            "ForensiRansom AI"
                        ),
                        "severity": metadata.get(
                            "severity",
                            "LOW"
                        ),
                        "mitre_technique": metadata.get(
                            "mitre_technique",
                            None
                        ),
                        "is_confirmed_ransomware": False,
                        "matched": True
                    })
        return results

    return results


def scan_text(text):
    """
    Scan text content using YARA rules.
    Safely handles rule loading errors without breaking callers.
    """
    if not text:
        return []

    try:
        rules = load_yara_rules()
        matches = rules.match(
            data=str(text)
        )
        return convert_matches(matches)
    except Exception as e:
        print(f"YARA scan_text warning: {e}")
        return []


def scan_file(file_path):
    """
    Scan a file using YARA rules.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    rules = load_yara_rules()
    matches = rules.match(
        filepath=file_path
    )
    return convert_matches(matches)


if __name__ == "__main__":
    print("Testing YARA Engine...")
    print(f"Rules Path: {get_yara_rules_path()} (Exists: {os.path.isfile(get_yara_rules_path())})")
    test_text = "vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No"
    matches = scan_text(test_text)
    print("Scan Matches count:", len(matches))
    for m in matches:
        print("  - Rule:", m["rule"], "| Severity:", m["severity"], "| MITRE:", m.get("mitre_technique"))
