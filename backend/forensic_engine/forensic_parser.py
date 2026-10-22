import os

# ============================================================
# FORENSIRANSOM AI
# FORENSIC RESULT PARSER
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
    
    # Fallback if deployed in unified container
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.basename(parent) == "backend":
        return os.path.dirname(parent)
    return parent


PROJECT_ROOT = resolve_project_root()

# Candidate directories where analysis results may reside
ANALYSIS_RESULTS_DIRS = [
    os.path.join(PROJECT_ROOT, "analysis_results"),
    os.path.join(PROJECT_ROOT, "backend", "analysis_results"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis_results"),
    os.path.join(os.getcwd(), "analysis_results"),
]

ANALYSIS_RESULTS_DIR = ANALYSIS_RESULTS_DIRS[0]


# ============================================================
# READ EVIDENCE-SPECIFIC RESULT FILE OR MEMORY BUFFER
# ============================================================

def read_result_file(
    evidence_id,
    result_name,
    raw_results_dict=None
):
    """
    Read the Volatility result belonging ONLY to the requested evidence ID.
    If raw_results_dict is provided (e.g. from active memory analysis or DB),
    it retrieves output directly from memory without disk dependency.
    Otherwise searches candidate directories on disk.
    """
    short_name = result_name.replace("windows.", "")

    # 1. Check in-memory results dictionary if provided
    if raw_results_dict and isinstance(raw_results_dict, dict):
        for candidate_key in [result_name, short_name, f"windows.{short_name}"]:
            if candidate_key in raw_results_dict:
                item = raw_results_dict[candidate_key]
                if isinstance(item, dict):
                    return item.get("raw_output", "")
                if isinstance(item, str):
                    return item

    # 2. Check candidate filenames on disk
    candidate_filenames = []
    if evidence_id:
        candidate_filenames.extend([
            f"{evidence_id}_{result_name}.txt",
            f"{evidence_id}_{short_name}.txt",
        ])
    candidate_filenames.extend([
        f"{result_name}.txt",
        f"{short_name}.txt",
    ])

    for base_dir in ANALYSIS_RESULTS_DIRS:
        if not os.path.isdir(base_dir):
            continue
        for fname in candidate_filenames:
            path = os.path.join(base_dir, fname)
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as file:
                        return file.read()
                except Exception as error:
                    print(f"Error reading result file {path}: {error}")

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

    if line.startswith("PID") or line.startswith("Offset") or line.startswith("Variable"):
        return True

    if line.startswith("Kernel") or line.startswith("Tree Depth") or line.startswith("Base"):
        return True

    if set(line) <= {"-", " ", "\t", "="}:
        return True

    return False


# ============================================================
# CREATE FORENSIC EVENT
# ============================================================

def create_event(
    event_type,
    source,
    raw_data,
    evidence_id,
    metadata=None
):
    event = {
        "event_type": event_type,
        "source": source,
        "evidence_id": evidence_id,
        "raw_data": raw_data,
        "evidence": {
            "raw_data": raw_data
        }
    }
    if metadata:
        event["metadata"] = metadata
    return event


# ============================================================
# PARSE PROCESS LIST
# ============================================================

def parse_pslist(evidence_id, raw_results_dict=None):
    output = read_result_file(evidence_id, "windows.pslist", raw_results_dict)
    events = []
    if not output:
        return events

    for line in output.splitlines():
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

def parse_pstree(evidence_id, raw_results_dict=None):
    output = read_result_file(evidence_id, "windows.pstree", raw_results_dict)
    events = []
    if not output:
        return events

    for line in output.splitlines():
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

def parse_psscan(evidence_id, raw_results_dict=None):
    output = read_result_file(evidence_id, "windows.psscan", raw_results_dict)
    events = []
    if not output:
        return events

    for line in output.splitlines():
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

def parse_netscan(evidence_id, raw_results_dict=None):
    output = read_result_file(evidence_id, "windows.netscan", raw_results_dict)
    events = []
    if not output:
        return events

    for line in output.splitlines():
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

def parse_cmdline(evidence_id, raw_results_dict=None):
    output = read_result_file(evidence_id, "windows.cmdline", raw_results_dict)
    events = []
    if not output:
        return events

    for line in output.splitlines():
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
# PARSE DLL AND MODULE LIST
# ============================================================

def parse_dlllist(evidence_id, raw_results_dict=None):
    output = read_result_file(evidence_id, "windows.dlllist", raw_results_dict)
    events = []
    if not output:
        return events

    for line in output.splitlines():
        line = line.strip()
        if is_header_or_separator(line):
            continue
        events.append(
            create_event(
                "MODULE_LOAD",
                "windows.dlllist",
                line,
                evidence_id
            )
        )
    return events


# ============================================================
# PARSE VAD AND MEMORY REGIONS
# ============================================================

def parse_vadinfo(evidence_id, raw_results_dict=None):
    output = read_result_file(evidence_id, "windows.vadinfo", raw_results_dict)
    events = []
    if not output:
        return events

    for line in output.splitlines():
        line = line.strip()
        if is_header_or_separator(line):
            continue
        # Check for RWX protections (PAGE_EXECUTE_READWRITE)
        is_rwx = "PAGE_EXECUTE_READWRITE" in line or "EXECUTE_READWRITE" in line
        events.append(
            create_event(
                "MEMORY_REGION",
                "windows.vadinfo",
                line,
                evidence_id,
                metadata={"is_rwx": is_rwx} if is_rwx else None
            )
        )
    return events


# ============================================================
# PARSE ALL FORENSIC RESULTS
# ============================================================

def parse_all_results(evidence_id="MEM-001", raw_results_dict=None):
    """
    Parse Volatility results belonging to the supplied evidence ID.
    Supports in-memory raw outputs and on-disk evidence results.
    """
    if not evidence_id:
        print("ERROR: Evidence ID is required for forensic parsing.")
        return []

    print("\n----------------------------------------")
    print("Evidence-Specific Forensic Parsing")
    print(f"Evidence ID: {evidence_id}")
    print("----------------------------------------")

    events = []

    # 1. PROCESS LIST
    pslist_events = parse_pslist(evidence_id, raw_results_dict)
    events.extend(pslist_events)
    print(f"windows.pslist: {len(pslist_events)} events")

    # 2. PROCESS TREE
    pstree_events = parse_pstree(evidence_id, raw_results_dict)
    events.extend(pstree_events)
    print(f"windows.pstree: {len(pstree_events)} events")

    # 3. PROCESS SCAN
    psscan_events = parse_psscan(evidence_id, raw_results_dict)
    events.extend(psscan_events)
    print(f"windows.psscan: {len(psscan_events)} events")

    # 4. NETWORK SCAN
    netscan_events = parse_netscan(evidence_id, raw_results_dict)
    events.extend(netscan_events)
    print(f"windows.netscan: {len(netscan_events)} events")

    # 5. COMMAND LINE
    cmdline_events = parse_cmdline(evidence_id, raw_results_dict)
    events.extend(cmdline_events)
    print(f"windows.cmdline: {len(cmdline_events)} events")

    # 6. DLL LIST
    dlllist_events = parse_dlllist(evidence_id, raw_results_dict)
    events.extend(dlllist_events)
    if dlllist_events:
        print(f"windows.dlllist: {len(dlllist_events)} events")

    # 7. VAD INFO
    vadinfo_events = parse_vadinfo(evidence_id, raw_results_dict)
    events.extend(vadinfo_events)
    if vadinfo_events:
        print(f"windows.vadinfo: {len(vadinfo_events)} events")

    print("----------------------------------------")
    print(f"Total parsed forensic events: {len(events)}")
    print(f"Evidence ID processed: {evidence_id}")
    print("----------------------------------------")

    return events


if __name__ == "__main__":
    print("Testing Forensic Parser on MEM-001...")
    events = parse_all_results("MEM-001")
    print(f"Total events parsed for MEM-001: {len(events)}")
