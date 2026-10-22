def correlate_events(analyzed_events):

    correlations = []
    seen_descriptions = set()

    command_events = []
    process_events = []
    network_events = []
    relationship_events = []
    memory_events = []
    module_events = []

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

        elif event_type == "MEMORY_REGION":
            memory_events.append(event)

        elif event_type == "MODULE_LOAD":
            module_events.append(event)

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
                "rundll32.exe",
                "vssadmin.exe",
                "certutil.exe"
            ]

            for process_name in common_processes:

                if (
                    process_name in command_lower
                    and process_name in process_lower
                ):
                    desc = f"{process_name} was observed in both process and command-line artifacts."
                    if desc not in seen_descriptions:
                        seen_descriptions.add(desc)
                        correlations.append({
                            "correlation_type": "PROCESS_COMMAND_CORRELATION",
                            "description": desc,
                            "severity": "HIGH",
                            "evidence": [command, process]
                        })

    # ---------------------------------
    # Correlation 2:
    # Suspicious command + network
    # ---------------------------------

    for command in command_events:

        if command.get("rule_score", 0) <= 0:
            continue

        for network in network_events:

            desc = "Command-line activity and network artifacts were observed in the same forensic investigation."
            if desc not in seen_descriptions:
                seen_descriptions.add(desc)
                correlations.append({
                    "correlation_type": "COMMAND_NETWORK_CORRELATION",
                    "description": desc,
                    "severity": "MEDIUM",
                    "evidence": [command, network]
                })

    # ---------------------------------
    # Correlation 3:
    # Suspicious process relationships
    # ---------------------------------

    for relationship in relationship_events:

        if relationship.get("rule_score", 0) > 0:

            desc = f"A process relationship contains an indicator requiring investigation: {relationship.get('indicators', ['Anomalous process tree'])[0]}"
            if desc not in seen_descriptions:
                seen_descriptions.add(desc)
                correlations.append({
                    "correlation_type": "PROCESS_RELATIONSHIP_CORRELATION",
                    "description": desc,
                    "severity": "MEDIUM",
                    "evidence": [relationship]
                })

    # ---------------------------------
    # Correlation 4:
    # Recovery tampering & Inhibition (T1490)
    # ---------------------------------

    for command in command_events:
        c_raw = command.get("evidence", {}).get("raw_data", "").lower()
        if any(keyword in c_raw for keyword in ["vssadmin delete", "shadowcopy delete", "wbadmin delete", "recoveryenabled no"]):
            desc = "System recovery inhibition (shadow copy deletion/bcdedit tampering) correlated with active process execution."
            if desc not in seen_descriptions:
                seen_descriptions.add(desc)
                correlations.append({
                    "correlation_type": "RECOVERY_TAMPERING_CORRELATION",
                    "description": desc,
                    "severity": "CRITICAL",
                    "evidence": [command]
                })

    # ---------------------------------
    # Correlation 5:
    # RWX Memory page + Scripting execution (T1055)
    # ---------------------------------

    for mem in memory_events:
        m_raw = mem.get("evidence", {}).get("raw_data", "")
        if "PAGE_EXECUTE_READWRITE" in m_raw or "EXECUTE_READWRITE" in m_raw:
            desc = "Executable/Writable (RWX) VAD memory allocation identified during memory triage (potential shellcode/injected payload)."
            if desc not in seen_descriptions:
                seen_descriptions.add(desc)
                correlations.append({
                    "correlation_type": "PROCESS_MEMORY_CORRELATION",
                    "description": desc,
                    "severity": "HIGH",
                    "evidence": [mem]
                })

    return correlations
