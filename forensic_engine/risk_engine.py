def calculate_risk_score(features):
    """
    Calculate an evidence-specific forensic risk score.

    The score is dynamically calculated from the forensic features
    extracted from the current evidence.

    Risk Levels:
        0-24   -> LOW
        25-49  -> MEDIUM
        50-74  -> HIGH
        75-100 -> CRITICAL
    """

    score = 0.0
    reasons = []
    contributions = {}

    # ============================================================
    # Helper function
    # ============================================================

    def add_score(name, value, reason=None):
        nonlocal score

        value = float(value)

        if value <= 0:
            return

        score += value
        contributions[name] = round(value, 2)

        if reason:
            reasons.append(reason)

    # ============================================================
    # 1. Rule-Based Detection
    # ============================================================

    rule_score = float(
        features.get("total_rule_score", 0) or 0
    )

    if rule_score > 0:

        rule_contribution = min(
            rule_score * 0.20,
            25
        )

        add_score(
            "rule_based_detection",
            rule_contribution,
            f"Rule-based forensic indicators contributed "
            f"{rule_contribution:.1f} risk points."
        )

    # ============================================================
    # 2. Suspicious Events
    # ============================================================

    suspicious_events = int(
        features.get("suspicious_events", 0) or 0
    )

    suspicious_contribution = min(
        suspicious_events * 3,
        15
    )

    add_score(
        "suspicious_events",
        suspicious_contribution,
        (
            f"{suspicious_events} suspicious forensic "
            f"event(s) were identified."
            if suspicious_events > 0
            else None
        )
    )

    # ============================================================
    # 3. High-Risk Events
    # ============================================================

    high_risk_events = int(
        features.get("high_risk_events", 0) or 0
    )

    high_risk_contribution = min(
        high_risk_events * 6,
        20
    )

    add_score(
        "high_risk_events",
        high_risk_contribution,
        (
            f"{high_risk_events} high-risk forensic "
            f"event(s) were identified."
            if high_risk_events > 0
            else None
        )
    )

    # ============================================================
    # 4. Medium-Risk Events
    # ============================================================

    medium_risk_events = int(
        features.get("medium_risk_events", 0) or 0
    )

    medium_risk_contribution = min(
        medium_risk_events * 2,
        10
    )

    add_score(
        "medium_risk_events",
        medium_risk_contribution,
        (
            f"{medium_risk_events} medium-risk forensic "
            f"event(s) were identified."
            if medium_risk_events > 0
            else None
        )
    )

    # ============================================================
    # 5. PowerShell Activity
    # ============================================================

    powershell_events = int(
        features.get("powershell_events", 0) or 0
    )

    powershell_contribution = min(
        powershell_events * 3,
        8
    )

    add_score(
        "powershell_activity",
        powershell_contribution,
        (
            f"{powershell_events} PowerShell-related "
            f"indicator(s) were detected."
            if powershell_events > 0
            else None
        )
    )

    # ============================================================
    # 6. Encoded Commands
    # ============================================================

    encoded_commands = int(
        features.get("encoded_command_events", 0) or 0
    )

    encoded_contribution = min(
        encoded_commands * 7,
        15
    )

    add_score(
        "encoded_commands",
        encoded_contribution,
        (
            f"{encoded_commands} encoded command "
            f"indicator(s) were detected."
            if encoded_commands > 0
            else None
        )
    )

    # ============================================================
    # 7. Suspicious Tools
    # ============================================================

    suspicious_tools = int(
        features.get("suspicious_tool_events", 0) or 0
    )

    suspicious_tool_contribution = min(
        suspicious_tools * 4,
        10
    )

    add_score(
        "suspicious_tools",
        suspicious_tool_contribution,
        (
            f"{suspicious_tools} suspicious tool "
            f"indicator(s) were detected."
            if suspicious_tools > 0
            else None
        )
    )

    # ============================================================
    # 8. YARA Matches
    # ============================================================

    yara_matches = int(
        features.get("yara_matches", 0) or 0
    )

    yara_contribution = min(
        yara_matches * 5,
        20
    )

    add_score(
        "yara_detection",
        yara_contribution,
        (
            f"{yara_matches} YARA rule match(es) "
            f"were detected."
            if yara_matches > 0
            else None
        )
    )

    # ============================================================
    # 9. Evidence Correlations
    # ============================================================

    correlation_count = int(
        features.get("correlation_count", 0) or 0
    )

    correlation_contribution = min(
        correlation_count * 3,
        10
    )

    add_score(
        "correlations",
        correlation_contribution,
        (
            f"{correlation_count} cross-artifact "
            f"correlation(s) were identified."
            if correlation_count > 0
            else None
        )
    )

    # ============================================================
    # 10. High-Severity Correlations
    # ============================================================

    high_correlations = int(
        features.get("high_severity_correlations", 0) or 0
    )

    high_correlation_contribution = min(
        high_correlations * 6,
        15
    )

    add_score(
        "high_severity_correlations",
        high_correlation_contribution,
        (
            f"{high_correlations} high-severity "
            f"correlation(s) were identified."
            if high_correlations > 0
            else None
        )
    )

    # ============================================================
    # 11. Medium-Severity Correlations
    # ============================================================

    medium_correlations = int(
        features.get("medium_severity_correlations", 0) or 0
    )

    medium_correlation_contribution = min(
        medium_correlations * 3,
        8
    )

    add_score(
        "medium_severity_correlations",
        medium_correlation_contribution,
        (
            f"{medium_correlations} medium-severity "
            f"correlation(s) were identified."
            if medium_correlations > 0
            else None
        )
    )

    # ============================================================
    # 12. Suspicious Event Ratio
    # ============================================================

    suspicious_ratio = float(
        features.get("suspicious_event_ratio", 0) or 0
    )

    # Handle both:
    # 0.25  -> 25%
    # 25.0  -> 25%
    if suspicious_ratio > 1:
        suspicious_ratio = suspicious_ratio / 100.0

    suspicious_ratio = max(
        0.0,
        min(suspicious_ratio, 1.0)
    )

    ratio_contribution = min(
        suspicious_ratio * 15,
        15
    )

    add_score(
        "suspicious_event_ratio",
        ratio_contribution,
        (
            f"Suspicious events represent approximately "
            f"{suspicious_ratio * 100:.1f}% of analyzed events."
            if suspicious_ratio > 0
            else None
        )
    )

    # ============================================================
    # 13. ML Ransomware Probability
    # ============================================================

    ml_ransomware_probability = float(
        features.get(
            "ml_ransomware_probability",
            features.get("ransomware_probability", 0)
        ) or 0
    )

    # Convert decimal probability if required.
    if 0 < ml_ransomware_probability <= 1:
        ml_ransomware_probability *= 100

    ml_ransomware_probability = max(
        0.0,
        min(ml_ransomware_probability, 100)
    )

    ransomware_ml_contribution = min(
        ml_ransomware_probability * 0.15,
        15
    )

    add_score(
        "ml_ransomware_probability",
        ransomware_ml_contribution,
        (
            f"ML analysis estimated a "
            f"{ml_ransomware_probability:.1f}% ransomware probability."
            if ml_ransomware_probability > 0
            else None
        )
    )

    # ============================================================
    # 14. ML Suspicious Probability
    # ============================================================

    ml_suspicious_probability = float(
        features.get(
            "ml_suspicious_probability",
            features.get("suspicious_probability", 0)
        ) or 0
    )

    if 0 < ml_suspicious_probability <= 1:
        ml_suspicious_probability *= 100

    ml_suspicious_probability = max(
        0.0,
        min(ml_suspicious_probability, 100)
    )

    suspicious_ml_contribution = min(
        ml_suspicious_probability * 0.05,
        5
    )

    add_score(
        "ml_suspicious_probability",
        suspicious_ml_contribution,
        (
            f"ML analysis estimated a "
            f"{ml_suspicious_probability:.1f}% suspicious probability."
            if ml_suspicious_probability > 0
            else None
        )
    )

    # ============================================================
    # 15. Maximum Rule Score
    # ============================================================

    maximum_rule_score = float(
        features.get("maximum_rule_score", 0) or 0
    )

    # Strong individual rule matches deserve additional weight,
    # but this contribution is deliberately capped.
    if maximum_rule_score > 0:

        maximum_rule_contribution = min(
            maximum_rule_score * 0.10,
            8
        )

        add_score(
            "maximum_rule_score",
            maximum_rule_contribution,
            (
                f"The strongest rule-based finding "
                f"had a score of {maximum_rule_score:.1f}."
            )
        )

    # ============================================================
    # Final score normalization
    # ============================================================

    score = max(
        0,
        min(round(score), 100)
    )

    # ============================================================
    # Risk level
    # ============================================================

    if score >= 75:

        risk_level = "CRITICAL"

    elif score >= 50:

        risk_level = "HIGH"

    elif score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # ============================================================
    # Default explanation
    # ============================================================

    if not reasons:

        reasons.append(
            "No significant forensic risk indicators "
            "were identified in the analyzed evidence."
        )

    # ============================================================
    # Final result
    # ============================================================

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "contributions": contributions,
        "indicators": {
            "total_rule_score": rule_score,
            "maximum_rule_score": maximum_rule_score,
            "suspicious_events": suspicious_events,
            "high_risk_events": high_risk_events,
            "medium_risk_events": medium_risk_events,
            "powershell_events": powershell_events,
            "encoded_command_events": encoded_commands,
            "suspicious_tool_events": suspicious_tools,
            "yara_matches": yara_matches,
            "correlation_count": correlation_count,
            "high_severity_correlations": high_correlations,
            "medium_severity_correlations": medium_correlations,
            "suspicious_event_ratio": round(
                suspicious_ratio,
                4
            ),
            "ml_ransomware_probability": round(
                ml_ransomware_probability,
                2
            ),
            "ml_suspicious_probability": round(
                ml_suspicious_probability,
                2
            )
        }
    }