import os


# ============================================================
# FORENSIRANSOM AI
# FORENSIC RESULT PARSER
# ============================================================

# Get the ForensiRansomAI project root directory
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# ANALYSIS RESULTS DIRECTORY
# ============================================================

ANALYSIS_RESULTS_DIR = os.path.join(
    PROJECT_ROOT,
    "analysis_results"
)


# ============================================================
# READ EVIDENCE-SPECIFIC RESULT FILE
# ============================================================

def read_result_file(
    evidence_id,
    result_name
):
    """
    Read the Volatility result belonging ONLY
    to the requested evidence ID.

    Example:

        MEM-001_windows.pslist.txt

    This prevents one evidence investigation from
    accidentally reading another evidence's results.
    """

    filename = (
        f"{evidence_id}_{result_name}.txt"
    )

    path = os.path.join(
        ANALYSIS_RESULTS_DIR,
        filename
    )

    if not os.path.exists(path):

        print(
            f"Result file not found: {path}"
        )

        return ""

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            return file.read()

    except Exception as error:

        print(
            f"Error reading result file "
            f"{filename}: {error}"
        )

        return ""


# ============================================================
# HEADER / SEPARATOR DETECTION
# ============================================================

def is_header_or_separator(line):

    line = line.strip()

    if not line:
        return True

    if line.startswith("Volatility"):
        return True

    if line.startswith("PID"):
        return True

    if line.startswith("Offset"):
        return True

    if line.startswith("Variable"):
        return True

    if line.startswith("Kernel"):
        return True

    if set(line) <= {
        "-",
        " "
    }:

        return True

    return False


# ============================================================
# CREATE FORENSIC EVENT
# ============================================================

def create_event(
    event_type,
    source,
    raw_data,
    evidence_id
):

    return {

        "event_type":
            event_type,

        "source":
            source,

        "evidence_id":
            evidence_id,

        "evidence": {

            "raw_data":
                raw_data
        }
    }


# ============================================================
# PARSE PROCESS LIST
# ============================================================

def parse_pslist(
    evidence_id
):

    output = read_result_file(
        evidence_id,
        "windows.pslist"
    )

    events = []

    if not output:

        return events

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if is_header_or_separator(line):

            continue

        events.append(
            create_event(

                "PROCESS_DETECTED",

                "windows.pslist",

                line,

                evidence_id
            )
        )

    return events


# ============================================================
# PARSE PROCESS TREE
# ============================================================

def parse_pstree(
    evidence_id
):

    output = read_result_file(
        evidence_id,
        "windows.pstree"
    )

    events = []

    if not output:

        return events

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if is_header_or_separator(line):

            continue

        events.append(
            create_event(

                "PROCESS_RELATIONSHIP",

                "windows.pstree",

                line,

                evidence_id
            )
        )

    return events


# ============================================================
# PARSE PROCESS SCAN
# ============================================================

def parse_psscan(
    evidence_id
):

    output = read_result_file(
        evidence_id,
        "windows.psscan"
    )

    events = []

    if not output:

        return events

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if is_header_or_separator(line):

            continue

        events.append(
            create_event(

                "PROCESS_SCAN",

                "windows.psscan",

                line,

                evidence_id
            )
        )

    return events


# ============================================================
# PARSE NETWORK CONNECTIONS
# ============================================================

def parse_netscan(
    evidence_id
):

    output = read_result_file(
        evidence_id,
        "windows.netscan"
    )

    events = []

    if not output:

        return events

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if is_header_or_separator(line):

            continue

        events.append(
            create_event(

                "NETWORK_CONNECTION",

                "windows.netscan",

                line,

                evidence_id
            )
        )

    return events


# ============================================================
# PARSE COMMAND LINE
# ============================================================

def parse_cmdline(
    evidence_id
):

    output = read_result_file(
        evidence_id,
        "windows.cmdline"
    )

    events = []

    if not output:

        return events

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if is_header_or_separator(line):

            continue

        events.append(
            create_event(

                "COMMAND_EXECUTION",

                "windows.cmdline",

                line,

                evidence_id
            )
        )

    return events


# ============================================================
# PARSE ALL FORENSIC RESULTS
# ============================================================

def parse_all_results(
    evidence_id
):

    """
    Parse ONLY the Volatility results belonging
    to the supplied evidence ID.

    Example:

        parse_all_results("MEM-002")

    will read:

        MEM-002_windows.pslist.txt
        MEM-002_windows.pstree.txt
        MEM-002_windows.psscan.txt
        MEM-002_windows.netscan.txt
        MEM-002_windows.cmdline.txt

    It will NEVER read MEM-001 results.
    """

    if not evidence_id:

        print(
            "ERROR: Evidence ID is required "
            "for forensic parsing."
        )

        return []

    print(
        "\n----------------------------------------"
    )

    print(
        "Evidence-Specific Forensic Parsing"
    )

    print(
        f"Evidence ID: {evidence_id}"
    )

    print(
        "----------------------------------------"
    )

    events = []

    # --------------------------------------------------------
    # PROCESS LIST
    # --------------------------------------------------------

    pslist_events = parse_pslist(
        evidence_id
    )

    events.extend(
        pslist_events
    )

    print(
        f"windows.pslist: "
        f"{len(pslist_events)} events"
    )

    # --------------------------------------------------------
    # PROCESS TREE
    # --------------------------------------------------------

    pstree_events = parse_pstree(
        evidence_id
    )

    events.extend(
        pstree_events
    )

    print(
        f"windows.pstree: "
        f"{len(pstree_events)} events"
    )

    # --------------------------------------------------------
    # PROCESS SCAN
    # --------------------------------------------------------

    psscan_events = parse_psscan(
        evidence_id
    )

    events.extend(
        psscan_events
    )

    print(
        f"windows.psscan: "
        f"{len(psscan_events)} events"
    )

    # --------------------------------------------------------
    # NETWORK SCAN
    # --------------------------------------------------------

    netscan_events = parse_netscan(
        evidence_id
    )

    events.extend(
        netscan_events
    )

    print(
        f"windows.netscan: "
        f"{len(netscan_events)} events"
    )

    # --------------------------------------------------------
    # COMMAND LINE
    # --------------------------------------------------------

    cmdline_events = parse_cmdline(
        evidence_id
    )

    events.extend(
        cmdline_events
    )

    print(
        f"windows.cmdline: "
        f"{len(cmdline_events)} events"
    )

    # --------------------------------------------------------
    # FINAL COUNT
    # --------------------------------------------------------

    print(
        "----------------------------------------"
    )

    print(
        f"Total parsed forensic events: "
        f"{len(events)}"
    )

    print(
        f"Evidence ID processed: "
        f"{evidence_id}"
    )

    print(
        "----------------------------------------"
    )

    return events