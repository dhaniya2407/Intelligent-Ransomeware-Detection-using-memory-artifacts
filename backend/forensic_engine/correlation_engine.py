def correlate_events(analyzed_events):

    correlations = []

    command_events = []
    process_events = []
    network_events = []
    relationship_events = []

    # ---------------------------------
    # Separate event types
    # ---------------------------------

    for event in analyzed_events:

        event_type = event.get("event_type")

        if event_type == "COMMAND_EXECUTION":
            command_events.append(event)

        elif event_type == "PROCESS_DETECTED":
            process_events.append(event)

        elif event_type == "NETWORK_CONNECTION":
            network_events.append(event)

        elif event_type == "PROCESS_RELATIONSHIP":
            relationship_events.append(event)

    # ---------------------------------
    # Correlation 1:
    # Suspicious command + process
    # ---------------------------------

    for command in command_events:

        if command.get("rule_score", 0) <= 0:
            continue

        command_data = command.get(
            "evidence",
            {}
        ).get(
            "raw_data",
            ""
        )

        for process in process_events:

            process_data = process.get(
                "evidence",
                {}
            ).get(
                "raw_data",
                ""
            )

            command_lower = command_data.lower()
            process_lower = process_data.lower()

            common_processes = [
                "powershell.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "rundll32.exe"
            ]

            for process_name in common_processes:

                if (
                    process_name in command_lower
                    and process_name in process_lower
                ):

                    correlations.append({
                        "correlation_type":
                            "PROCESS_COMMAND_CORRELATION",

                        "description":
                            f"{process_name} was observed "
                            "in both process and command-line artifacts.",

                        "severity":
                            "HIGH",

                        "evidence": [
                            command,
                            process
                        ]
                    })

    # ---------------------------------
    # Correlation 2:
    # Suspicious command + network
    # ---------------------------------

    for command in command_events:

        if command.get("rule_score", 0) <= 0:
            continue

        for network in network_events:

            correlations.append({
                "correlation_type":
                    "COMMAND_NETWORK_CORRELATION",

                "description":
                    "Command-line activity and network "
                    "artifacts were observed in the "
                    "same forensic investigation.",

                "severity":
                    "MEDIUM",

                "evidence": [
                    command,
                    network
                ]
            })

    # ---------------------------------
    # Correlation 3:
    # Suspicious process relationships
    # ---------------------------------

    for relationship in relationship_events:

        if relationship.get("rule_score", 0) > 0:

            correlations.append({
                "correlation_type":
                    "PROCESS_RELATIONSHIP_CORRELATION",

                "description":
                    "A process relationship contains "
                    "an indicator requiring investigation.",

                "severity":
                    "MEDIUM",

                "evidence": [
                    relationship
                ]
            })

    return correlations