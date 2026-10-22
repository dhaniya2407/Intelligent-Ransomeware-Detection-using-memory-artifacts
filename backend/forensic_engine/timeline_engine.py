def create_timeline_event(
    event_type,
    what,
    why,
    source,
    severity="INFO",
    evidence=None
):
    return {
        "event_type": event_type,
        "what": what,
        "why": why,
        "source": source,
        "severity": severity,
        "evidence": evidence or {}
    }


def get_raw_data(event):
    """
    Extract raw forensic evidence from the parsed event.

    The parser stores raw data inside:
    event["evidence"]["raw_data"]

    A fallback is included for compatibility with older
    event structures.
    """

    evidence = event.get("evidence", {})

    if isinstance(evidence, dict):
        raw_data = evidence.get("raw_data", "")

        if raw_data:
            return raw_data

    # Fallback for older parser format
    return event.get("raw_data", "")


def build_timeline(events):

    timeline = []

    for event in events:

        event_type = event.get("event_type")
        source = event.get("source")

        # Correctly extract nested raw forensic evidence
        raw_data = get_raw_data(event)

        # ---------------------------------
        # PROCESS EVENTS
        # ---------------------------------

        if event_type == "PROCESS_DETECTED":

            timeline.append(
                create_timeline_event(
                    event_type="PROCESS_DETECTED",
                    what="A process was detected in the memory image.",
                    why=(
                        "The process exists in the captured system memory "
                        "and should be examined as part of the investigation."
                    ),
                    source=source,
                    severity="INFO",
                    evidence={
                        "raw_data": raw_data
                    }
                )
            )

        # ---------------------------------
        # PROCESS RELATIONSHIPS
        # ---------------------------------

        elif event_type == "PROCESS_RELATIONSHIP":

            timeline.append(
                create_timeline_event(
                    event_type="PROCESS_RELATIONSHIP",
                    what="A process relationship was observed.",
                    why=(
                        "Parent-child process relationships can help "
                        "reconstruct how processes were launched."
                    ),
                    source=source,
                    severity="INFO",
                    evidence={
                        "raw_data": raw_data
                    }
                )
            )

        # ---------------------------------
        # PROCESS SCAN
        # ---------------------------------

        elif event_type == "PROCESS_SCAN":

            timeline.append(
                create_timeline_event(
                    event_type="PROCESS_SCAN",
                    what="A process was identified during memory scanning.",
                    why=(
                        "Memory scanning can reveal process artifacts "
                        "that require comparison with the active process list."
                    ),
                    source=source,
                    severity="MEDIUM",
                    evidence={
                        "raw_data": raw_data
                    }
                )
            )

        # ---------------------------------
        # NETWORK EVENTS
        # ---------------------------------

        elif event_type == "NETWORK_CONNECTION":

            timeline.append(
                create_timeline_event(
                    event_type="NETWORK_CONNECTION",
                    what="A network connection artifact was detected.",
                    why=(
                        "Network activity can provide evidence of "
                        "communication between the investigated system "
                        "and other endpoints."
                    ),
                    source=source,
                    severity="MEDIUM",
                    evidence={
                        "raw_data": raw_data
                    }
                )
            )

        # ---------------------------------
        # COMMAND-LINE EVENTS
        # ---------------------------------

        elif event_type == "COMMAND_EXECUTION":

            timeline.append(
                create_timeline_event(
                    event_type="COMMAND_EXECUTION",
                    what="Command-line activity was detected.",
                    why=(
                        "Command-line activity can reveal programs "
                        "or commands executed on the investigated system."
                    ),
                    source=source,
                    severity="MEDIUM",
                    evidence={
                        "raw_data": raw_data
                    }
                )
            )

        # ---------------------------------
        # MODULE & DLL EVENTS
        # ---------------------------------

        elif event_type == "MODULE_LOAD":

            timeline.append(
                create_timeline_event(
                    event_type="MODULE_LOAD",
                    what="Dynamic Link Library (DLL) loaded by process.",
                    why=(
                        "Loaded libraries reveal module dependencies, potential DLL search-order hijacking, "
                        "and cryptographic or networking capabilities."
                    ),
                    source=source,
                    severity="INFO",
                    evidence={
                        "raw_data": raw_data
                    }
                )
            )

        # ---------------------------------
        # MEMORY REGION (VAD) EVENTS
        # ---------------------------------

        elif event_type == "MEMORY_REGION":

            is_rwx = event.get("metadata", {}).get("is_rwx", False) or "PAGE_EXECUTE_READWRITE" in raw_data
            timeline.append(
                create_timeline_event(
                    event_type="MEMORY_REGION",
                    what="Executable memory allocation observed in process VAD.",
                    why=(
                        "Executable and writable (RWX) memory pages frequently host injected shellcode, "
                        "unpacked payloads, or reflective DLLs."
                        if is_rwx else
                        "Memory page protections indicate loaded code sections and potential code injection."
                    ),
                    source=source,
                    severity="HIGH" if is_rwx else "INFO",
                    evidence={
                        "raw_data": raw_data
                    }
                )
            )

    return timeline
