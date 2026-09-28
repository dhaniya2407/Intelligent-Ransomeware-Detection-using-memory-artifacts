import sqlite3

connection = sqlite3.connect("database/forensic.db")
cursor = connection.cursor()

# 1. CASES
cursor.execute("""
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_name TEXT NOT NULL,
    investigator TEXT,
    description TEXT,
    status TEXT DEFAULT 'Open',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
""")

# 2. EVIDENCE
cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    filename TEXT NOT NULL,
    evidence_type TEXT,
    file_size INTEGER,
    sha256 TEXT,
    source TEXT,
    status TEXT DEFAULT 'Verified',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
)
""")

# 3. PROCESSES
cursor.execute("""
CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER,
    pid INTEGER,
    process_name TEXT,
    parent_pid INTEGER,
    command_line TEXT,
    risk_level TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
)
""")

# 4. NETWORK ARTIFACTS
cursor.execute("""
CREATE TABLE IF NOT EXISTS network_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER,
    process_name TEXT,
    pid INTEGER,
    local_address TEXT,
    remote_address TEXT,
    remote_port INTEGER,
    risk_level TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
)
""")

# 5. YARA RESULTS
cursor.execute("""
CREATE TABLE IF NOT EXISTS yara_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER,
    rule_name TEXT,
    artifact TEXT,
    match_details TEXT,
    severity TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
)
""")

# 6. IOCs
cursor.execute("""
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER,
    ioc_type TEXT,
    ioc_value TEXT,
    source TEXT,
    severity TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
)
""")

# 7. AI PREDICTIONS
cursor.execute("""
CREATE TABLE IF NOT EXISTS ai_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    prediction TEXT,
    confidence REAL,
    model_name TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
)
""")

# 8. RISK ASSESSMENTS
cursor.execute("""
CREATE TABLE IF NOT EXISTS risk_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    risk_score REAL,
    risk_level TEXT,
    explanation TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
)
""")

# 9. TIMELINE
cursor.execute("""
CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    event_time TEXT,
    event_type TEXT,
    description TEXT,
    source TEXT,
    severity TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id)
)
""")

# 10. REPORTS
cursor.execute("""
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    report_name TEXT,
    report_path TEXT,
    generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
)
""")

# 11. AUDIT LOG
cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    user_name TEXT,
    action TEXT,
    details TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
)
""")

connection.commit()
connection.close()

print("ForensiRansom AI database created successfully!")