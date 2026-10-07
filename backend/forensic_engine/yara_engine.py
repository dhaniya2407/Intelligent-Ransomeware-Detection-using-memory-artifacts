import os
import yara


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

YARA_RULES_PATH = os.path.join(
    PROJECT_ROOT,
    "yara_rules",
    "ransomware_rules.yar"
)


def load_yara_rules():
    """
    Load YARA rules from the project rules directory.
    """

    if not os.path.exists(YARA_RULES_PATH):
        raise FileNotFoundError(
            f"YARA rules file not found: {YARA_RULES_PATH}"
        )

    return yara.compile(
        filepath=YARA_RULES_PATH
    )


def convert_matches(matches):
    """
    Convert YARA results into a consistent
    ForensiRansom AI result format.
    """

    results = []

    # Standard yara-python format:
    # A list of Match objects
    if isinstance(matches, list):

        for match in matches:

            if isinstance(match, str):

                results.append({
                    "rule": match,
                    "description": "YARA rule matched.",
                    "author": "ForensiRansom AI",
                    "severity": "LOW",
                    "matched": True
                })

            else:

                metadata = getattr(
                    match,
                    "meta",
                    {}
                )

                results.append({
                    "rule": getattr(
                        match,
                        "rule",
                        "Unknown"
                    ),
                    "description": metadata.get(
                        "description",
                        "No description available."
                    ),
                    "author": metadata.get(
                        "author",
                        "Unknown"
                    ),
                    "severity": metadata.get(
                        "severity",
                        "LOW"
                    ),
                    "matched": True
                })

        return results

    # Dictionary-based result format
    if isinstance(matches, dict):

        for category, match_items in matches.items():

            if not isinstance(match_items, list):
                continue

            for match in match_items:

                if isinstance(match, dict):

                    metadata = match.get(
                        "meta",
                        {}
                    )

                    results.append({
                        "rule": match.get(
                            "rule",
                            "Unknown"
                        ),
                        "description": metadata.get(
                            "description",
                            "No description available."
                        ),
                        "author": metadata.get(
                            "author",
                            "Unknown"
                        ),
                        "severity": metadata.get(
                            "severity",
                            "LOW"
                        ),
                        "matched": match.get(
                            "matches",
                            True
                        )
                    })

                elif isinstance(match, str):

                    results.append({
                        "rule": match,
                        "description": "YARA rule matched.",
                        "author": "ForensiRansom AI",
                        "severity": "LOW",
                        "matched": True
                    })

        return results

    return results


def scan_text(text):
    """
    Scan text content using YARA rules.
    """

    if not text:
        return []

    rules = load_yara_rules()

    matches = rules.match(
        data=str(text)
    )

    return convert_matches(matches)


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