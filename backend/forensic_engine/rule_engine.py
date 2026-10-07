def get_raw_data(event):
    """
    Extract raw data from a forensic event.

    Timeline events usually store raw data inside:
    event["evidence"]["raw_data"]

    This function also supports events where raw_data
    is stored directly inside the event.
    """

    evidence = event.get("evidence", {})

    if isinstance(evidence, dict):

        raw_data = evidence.get("raw_data", "")

        if raw_data:
            return str(raw_data)

    return str(event.get("raw_data", ""))


def check_command_line(event):
    """
    Detect suspicious command-line behavior.

    Encoded PowerShell detection is performed only when
    PowerShell is explicitly present in the command line.
    """

    raw_data = get_raw_data(event).lower()

    indicators = []
    score = 0

    # -------------------------------------------------
    # PowerShell detection
    # -------------------------------------------------

    powershell_detected = (
        "powershell.exe" in raw_data
        or "powershell " in raw_data
        or "\\powershell" in raw_data
    )

    if powershell_detected:

        indicators.append(
            "PowerShell execution detected"
        )

        score += 20

        # ---------------------------------------------
        # Encoded PowerShell detection
        # ---------------------------------------------

        encoded_flags = [
            " -enc ",
            " -encodedcommand ",
            " -enc\t",
            " -encodedcommand\t",
            " -enc\r\n",
            " -encodedcommand\r\n"
        ]

        encoded_detected = any(
            flag in raw_data
            for flag in encoded_flags
        )

        if encoded_detected:

            indicators.append(
                "Encoded PowerShell command detected"
            )

            score += 30

    # -------------------------------------------------
    # Common scripting interpreters
    # -------------------------------------------------

    suspicious_tools = [
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe"
    ]

    for tool in suspicious_tools:

        if tool in raw_data:

            indicators.append(
                f"Suspicious execution tool detected: {tool}"
            )

            score += 15

    return {
        "score": score,
        "indicators": indicators
    }


def check_process(event):
    """
    Detect process names that require investigation.
    """

    raw_data = get_raw_data(event).lower()

    indicators = []
    score = 0

    suspicious_processes = [
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe"
    ]

    for process in suspicious_processes:

        if process in raw_data:

            indicators.append(
                f"Suspicious process observed: {process}"
            )

            score += 20

    return {
        "score": score,
        "indicators": indicators
    }


def check_network(event):
    """
    Detect network artifacts requiring investigation.

    A network artifact alone does not prove malicious activity.
    It is treated as an investigation indicator.
    """

    raw_data = get_raw_data(event).lower()

    indicators = []
    score = 0

    if raw_data:

        indicators.append(
            "Network connection artifact observed"
        )

        score += 5

    return {
        "score": score,
        "indicators": indicators
    }


def analyze_event(event):
    """
    Analyze one forensic event using the appropriate rule set.
    """

    event_type = event.get("event_type")

    total_score = 0
    indicators = []

    if event_type == "COMMAND_EXECUTION":

        result = check_command_line(event)

        total_score += result["score"]
        indicators.extend(result["indicators"])

    elif event_type == "PROCESS_DETECTED":

        result = check_process(event)

        total_score += result["score"]
        indicators.extend(result["indicators"])

    elif event_type == "NETWORK_CONNECTION":

        result = check_network(event)

        total_score += result["score"]
        indicators.extend(result["indicators"])

    return {
        "score": total_score,
        "indicators": indicators
    }


def analyze_timeline(timeline):
    """
    Apply the rule engine to all timeline events.

    Adds:
    - rule_score
    - indicators
    - risk_level
    """

    analyzed_events = []

    for event in timeline:

        result = analyze_event(event)

        analyzed_event = event.copy()

        analyzed_event["rule_score"] = result["score"]

        analyzed_event["indicators"] = (
            result["indicators"]
        )

        if result["score"] >= 50:

            analyzed_event["risk_level"] = "HIGH"

        elif result["score"] >= 20:

            analyzed_event["risk_level"] = "MEDIUM"

        else:

            analyzed_event["risk_level"] = "LOW"

        analyzed_events.append(analyzed_event)

    return analyzed_events