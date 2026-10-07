def extract_features(
    analyzed_events,
    correlations,
    yara_matches=None,
    ml_prediction=None
):
    """
    Convert forensic investigation results into numerical
    features for ML/DL and dynamic risk assessment.

    Features are generated from the currently analyzed evidence.
    No evidence ID, case ID, filename, or fixed risk value is used.
    """

    features = {}

    # ============================================================
    # Basic event counts
    # ============================================================

    features["total_events"] = len(analyzed_events)

    features["process_events"] = 0
    features["process_scan_events"] = 0
    features["network_events"] = 0
    features["command_events"] = 0
    features["relationship_events"] = 0

    # ============================================================
    # Suspicious behavior counts
    # ============================================================

    features["suspicious_events"] = 0
    features["high_risk_events"] = 0
    features["medium_risk_events"] = 0

    features["powershell_events"] = 0
    features["encoded_command_events"] = 0
    features["suspicious_tool_events"] = 0

    # ============================================================
    # Rule-based detection
    # ============================================================

    features["total_rule_score"] = 0
    features["maximum_rule_score"] = 0

    # ============================================================
    # Process / forensic events
    # ============================================================

    for event in analyzed_events:

        event_type = event.get(
            "event_type",
            ""
        )

        score = event.get(
            "rule_score",
            0
        )

        risk_level = event.get(
            "risk_level",
            "LOW"
        )

        indicators = event.get(
            "indicators",
            []
        )

        # --------------------------------------------------------
        # Event type counts
        # --------------------------------------------------------

        if event_type == "PROCESS_DETECTED":

            features["process_events"] += 1

        elif event_type == "PROCESS_SCAN":

            features["process_scan_events"] += 1

        elif event_type == "NETWORK_CONNECTION":

            features["network_events"] += 1

        elif event_type == "COMMAND_EXECUTION":

            features["command_events"] += 1

        elif event_type == "PROCESS_RELATIONSHIP":

            features["relationship_events"] += 1

        # --------------------------------------------------------
        # Risk counts
        # --------------------------------------------------------

        if score > 0:

            features["suspicious_events"] += 1

        if risk_level == "HIGH":

            features["high_risk_events"] += 1

        elif risk_level == "MEDIUM":

            features["medium_risk_events"] += 1

        # --------------------------------------------------------
        # Rule scores
        # --------------------------------------------------------

        try:
            score = float(score)
        except (TypeError, ValueError):

            score = 0

        features["total_rule_score"] += score

        if score > features["maximum_rule_score"]:

            features["maximum_rule_score"] = score

        # --------------------------------------------------------
        # Indicator analysis
        # --------------------------------------------------------

        if not isinstance(indicators, list):

            indicators = [indicators]

        for indicator in indicators:

            indicator_lower = str(
                indicator
            ).lower()

            # PowerShell
            if "powershell" in indicator_lower:

                features["powershell_events"] += 1

            # Encoded commands
            if (
                "encoded" in indicator_lower
                or "base64" in indicator_lower
                or "-enc" in indicator_lower
            ):

                features["encoded_command_events"] += 1

            # Suspicious tools
            suspicious_tool_keywords = [
                "mimikatz",
                "procdump",
                "psexec",
                "wmic",
                "certutil",
                "bitsadmin",
                "rundll32",
                "regsvr32",
                "mshta",
                "cscript",
                "wscript",
                "suspicious tool"
            ]

            if any(
                keyword in indicator_lower
                for keyword in suspicious_tool_keywords
            ):

                features["suspicious_tool_events"] += 1

    # ============================================================
    # Correlation features
    # ============================================================

    if correlations is None:

        correlations = []

    features["correlation_count"] = len(
        correlations
    )

    features["high_severity_correlations"] = 0

    features["medium_severity_correlations"] = 0

    for correlation in correlations:

        severity = str(
            correlation.get(
                "severity",
                "LOW"
            )
        ).upper()

        if severity == "HIGH":

            features[
                "high_severity_correlations"
            ] += 1

        elif severity == "MEDIUM":

            features[
                "medium_severity_correlations"
            ] += 1

    # ============================================================
    # YARA features
    # ============================================================

    if yara_matches is None:

        yara_matches = []

    # Support both:
    #
    # yara_matches = list
    #
    # and:
    #
    # yara_matches = {"matches": [...]}
    #
    if isinstance(yara_matches, dict):

        yara_match_list = yara_matches.get(
            "matches",
            yara_matches.get(
                "findings",
                []
            )
        )

    else:

        yara_match_list = yara_matches

    if yara_match_list is None:

        yara_match_list = []

    features["yara_matches"] = len(
        yara_match_list
    )

    # ============================================================
    # YARA rule count
    # ============================================================

    yara_rule_names = set()

    for match in yara_match_list:

        if isinstance(match, dict):

            rule_name = (
                match.get("rule")
                or match.get("rule_name")
                or match.get("name")
            )

            if rule_name:

                yara_rule_names.add(
                    str(rule_name)
                )

        else:

            yara_rule_names.add(
                str(match)
            )

    features["yara_rules_detected"] = len(
        yara_rule_names
    )

    # ============================================================
    # Derived suspicious event ratio
    # ============================================================

    if features["total_events"] > 0:

        features["suspicious_event_ratio"] = (
            features["suspicious_events"]
            / features["total_events"]
        )

    else:

        features["suspicious_event_ratio"] = 0.0

    # ============================================================
    # ML prediction features
    # ============================================================

    features["ml_ransomware_probability"] = 0.0

    features["ml_suspicious_probability"] = 0.0

    features["ml_normal_probability"] = 0.0

    features["ml_classification"] = "Unknown"

    if isinstance(ml_prediction, dict):

        # --------------------------------------------------------
        # Classification
        # --------------------------------------------------------

        classification = (
            ml_prediction.get("classification")
            or ml_prediction.get("prediction")
            or ml_prediction.get("label")
            or ml_prediction.get("class")
        )

        if classification:

            features[
                "ml_classification"
            ] = str(classification)

        # --------------------------------------------------------
        # Probability dictionary
        # --------------------------------------------------------

        probabilities = (
            ml_prediction.get("probabilities")
            or ml_prediction.get("probability")
            or {}
        )

        if isinstance(probabilities, dict):

            features[
                "ml_ransomware_probability"
            ] = float(
                probabilities.get(
                    "Ransomware",
                    probabilities.get(
                        "ransomware",
                        0
                    )
                ) or 0
            )

            features[
                "ml_suspicious_probability"
            ] = float(
                probabilities.get(
                    "Suspicious",
                    probabilities.get(
                        "suspicious",
                        0
                    )
                ) or 0
            )

            features[
                "ml_normal_probability"
            ] = float(
                probabilities.get(
                    "Normal",
                    probabilities.get(
                        "normal",
                        0
                    )
                ) or 0
            )

        # --------------------------------------------------------
        # Direct probability fields
        # --------------------------------------------------------

        features[
            "ml_ransomware_probability"
        ] = float(
            ml_prediction.get(
                "ransomware_probability",
                features[
                    "ml_ransomware_probability"
                ]
            ) or 0
        )

        features[
            "ml_suspicious_probability"
        ] = float(
            ml_prediction.get(
                "suspicious_probability",
                features[
                    "ml_suspicious_probability"
                ]
            ) or 0
        )

        features[
            "ml_normal_probability"
        ] = float(
            ml_prediction.get(
                "normal_probability",
                features[
                    "ml_normal_probability"
                ]
            ) or 0
        )

    # ============================================================
    # Normalize ML probabilities
    # ============================================================

    for key in [
        "ml_ransomware_probability",
        "ml_suspicious_probability",
        "ml_normal_probability"
    ]:

        value = features[key]

        # Convert 0.78 → 78
        if 0 < value <= 1:

            value *= 100

        features[key] = round(
            max(
                0,
                min(value, 100)
            ),
            2
        )

    # ============================================================
    # Final numeric cleanup
    # ============================================================

    features["total_rule_score"] = round(
        features["total_rule_score"],
        2
    )

    features["maximum_rule_score"] = round(
        features["maximum_rule_score"],
        2
    )

    features["suspicious_event_ratio"] = round(
        features["suspicious_event_ratio"],
        4
    )

    return features