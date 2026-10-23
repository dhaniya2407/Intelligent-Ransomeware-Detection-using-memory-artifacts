# ============================================================
# FORENSIRANSOM AI
# AI-BASED INTELLIGENT RANSOMWARE DETECTION
# AND AUTOMATED DIGITAL FORENSIC INVESTIGATION
# ============================================================

import os
import sys
import json
import hashlib
import subprocess
from typing import Optional

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Request
)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt
from sqlalchemy.orm import Session


# ============================================================
# PROJECT PATH
# IMPORTANT:
# PROJECT_ROOT MUST BE ADDED BEFORE ml_engine IMPORTS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ============================================================
# DATABASE / MODELS
# ============================================================

from sqlalchemy import func
from database import engine, SessionLocal, Base

from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    get_current_user_from_request,
    get_user_case,
    get_user_evidence,
    check_login_rate_limit,
    record_failed_login,
    clear_login_attempts
)

from models import (
    Case,
    User,
    Evidence,
    AnalysisResult
)


# ============================================================
# FORENSIC ENGINE IMPORTS
# ============================================================

from forensic_engine.volatility_engine import (
    analyze_memory
)

from forensic_engine.forensic_parser import (
    parse_all_results
)

from forensic_engine.timeline_engine import (
    build_timeline
)

from forensic_engine.rule_engine import (
    analyze_timeline
)

from forensic_engine.correlation_engine import (
    correlate_events
)

from forensic_engine.feature_engine import (
    extract_features
)

from forensic_engine.risk_engine import (
    calculate_risk_score
)

from forensic_engine.yara_engine import (
    scan_text
)

from ml_engine.predictor import predict

from reports.gemini_service import get_recommendations
from reports.generator import (
    generate_pdf_report,
    generate_json_report,
    generate_evidence_log
)


# ============================================================
# VOLATILITY CONFIGURATION
# ============================================================

VOLATILITY_PATH = (
    r"C:\Users\dhani\Downloads"
    r"\volatility3-win-exes-2.28.0"
    r"\vol.exe"
)


# ============================================================
# ============================================================
# CREATE DATABASE TABLES & SEED INITIAL USER
# ============================================================

Base.metadata.create_all(
    bind=engine
)

def seed_initial_users():
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "dhaniya").first()
        if not existing:
            default_user = User(
                username="dhaniya",
                email="christydhaniya@gmail.com",
                password_hash="$2b$12$Iv8rY734LnFSlOHb9YprNed6KllOXALJSy4Vxj.EozmOCopFFA0Ie",
                role="Investigator"
            )
            db.add(default_user)
            db.commit()
    except Exception as e:
        print("Initial user seed warning:", e)
        db.rollback()
    finally:
        db.close()

seed_initial_users()

def ensure_schema_and_migration():
    db = SessionLocal()
    try:
        from sqlalchemy import text
        res = db.execute(text("PRAGMA table_info(cases);")).fetchall()
        cols = [r[1] for r in res]
        if "user_id" not in cols:
            db.execute(text("ALTER TABLE cases ADD COLUMN user_id INTEGER REFERENCES users(id);"))
            db.commit()

        owner = db.query(User).filter(User.username == "dhaniya").first()
        if owner:
            db.execute(
                text("UPDATE cases SET user_id = :uid WHERE (user_id IS NULL OR user_id = 0) AND (LOWER(investigator) LIKE '%dhaniya%');"),
                {"uid": owner.id}
            )
            db.commit()
    except Exception as e:
        print("Schema/migration check warning:", e)
        db.rollback()
    finally:
        db.close()

ensure_schema_and_migration()


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ForensiRansom AI",
    description=(
        "AI-Based Intelligent Ransomware Detection "
        "and Automated Digital Forensic Investigation"
    ),
    version="1.0.0"
)

# ============================================================
# FRONTEND STATIC FILES CONFIGURATION
# ============================================================

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIST = os.path.join(PROJECT_ROOT, "frontend", "dist")
if not os.path.isdir(FRONTEND_DIST):
    FRONTEND_DIST = os.path.join(BACKEND_DIR, "static")

assets_dir = os.path.join(FRONTEND_DIST, "assets")
if os.path.isdir(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/")
def root():
    index_html = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.isfile(index_html):
        return FileResponse(index_html)
    return {
        "message": "ForensiRansom AI Backend is working",
        "version": "1.0.0"
    }
# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# DATABASE SESSION
# ============================================================

def get_db():

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# ============================================================
# USER AUTHENTICATION SCHEMAS
# ============================================================

class UserRegister(BaseModel):

    username: str
    email: str
    password: str
    role: str = "Investigator"


class UserLogin(BaseModel):

    username: str
    password: str


# ============================================================
# USER REGISTRATION API
# ============================================================

@app.post("/register")
def register_user(
    user: UserRegister,
    db: Session = Depends(get_db)
):
    norm_username = user.username.strip().lower()
    norm_email = user.email.strip().lower()

    if not norm_username or len(norm_username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters long"
        )
    if not user.password or len(user.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters long"
        )

    # Check unique username
    existing_user = db.query(User).filter(
        func.lower(User.username) == norm_username
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    # Check unique email
    existing_email = db.query(User).filter(
        func.lower(User.email) == norm_email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # Create new user
    new_user = User(
        username=norm_username,
        email=norm_email,
        password_hash=hash_password(user.password),
        role=user.role or "Investigator"
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token = create_access_token(
        data={"sub": str(new_user.id), "username": new_user.username, "role": new_user.role}
    )

    return {
        "message": "User registered successfully",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "role": new_user.role
        }
    }


# ============================================================
# USER LOGIN API
# ============================================================

@app.post("/login")
def login_user(
    user: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    norm_username = user.username.strip().lower()

    # Enforce brute-force rate limit
    check_login_rate_limit(client_ip, norm_username)

    db_user = db.query(User).filter(
        (func.lower(User.username) == norm_username) |
        (func.lower(User.email) == norm_username)
    ).first()

    if not db_user or not verify_password(user.password, db_user.password_hash):
        record_failed_login(client_ip, norm_username)
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Successful login: clear attempt history and issue JWT
    clear_login_attempts(client_ip, norm_username)
    access_token = create_access_token(
        data={"sub": str(db_user.id), "username": db_user.username, "role": db_user.role}
    )

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
            "role": db_user.role
        }
    }


# ============================================================
# CURRENT USER & LOGOUT APIs
# ============================================================

@app.get("/auth/me")
def get_auth_me(
    current_user: User = Depends(get_current_user)
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role
    }


@app.post("/auth/logout")
def logout_user():
    return {
        "message": "Logged out successfully"
    }


# ============================================================
# CASE SCHEMAS
# ============================================================

class CaseCreate(BaseModel):
    case_name: str
    investigator: str
    description: Optional[str] = None
    status: str = "Open"


class CaseUpdate(BaseModel):

    case_name: Optional[str] = None
    investigator: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


# ============================================================
# API STATUS ENDPOINT
# ============================================================

@app.get("/api/status")
def api_status():

    return {

        "application":
            "ForensiRansom AI",

        "status":
            "running",

        "message":
            "ForensiRansom AI Backend is working"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():

    return {

        "status":
            "healthy"
    }

# ============================================================
# DYNAMIC CASE ID GENERATOR
# ============================================================

def generate_next_case_id(db: Session) -> str:

    existing_cases = db.query(
        Case.case_id
    ).all()

    highest_number = 0

    for row in existing_cases:

        case_id = row[0]

        if not case_id:
            continue

        if case_id.startswith("FRA-"):

            try:

                number = int(
                    case_id.replace(
                        "FRA-",
                        ""
                    )
                )

                highest_number = max(
                    highest_number,
                    number
                )

            except ValueError:
                continue

    return f"FRA-{highest_number + 1:03d}"


# ============================================================
# DYNAMIC EVIDENCE ID GENERATOR
# ============================================================

def generate_next_evidence_id(db: Session) -> str:

    existing_evidence = db.query(
        Evidence.evidence_id
    ).all()

    highest_number = 0

    for row in existing_evidence:

        evidence_id = row[0]

        if not evidence_id:
            continue

        if evidence_id.startswith("MEM-"):

            try:

                number = int(
                    evidence_id.replace(
                        "MEM-",
                        ""
                    )
                )

                highest_number = max(
                    highest_number,
                    number
                )

            except ValueError:
                continue

    return f"MEM-{highest_number + 1:03d}"

# ============================================================
# CREATE CASE
# DYNAMIC CASE ID
# ============================================================

@app.post("/cases")
def create_case(
    case_data: CaseCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Generate Case ID automatically
    case_id = generate_next_case_id(db)

    # Create case strictly associated with authenticated user
    new_case = Case(
        case_id=case_id,
        user_id=current_user.id,
        case_name=case_data.case_name,
        investigator=case_data.investigator or current_user.username,
        description=case_data.description,
        status=case_data.status
    )

    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    return {
        "message": "Case created successfully",
        "case": {
            "case_id": new_case.case_id,
            "case_name": new_case.case_name,
            "investigator": new_case.investigator,
            "description": new_case.description,
            "status": new_case.status
        }
    }

# ============================================================
# GET ALL CASES
# ============================================================

@app.get("/cases")
def get_cases(
    request: Request,
    db: Session = Depends(get_db)
):
    accept = request.headers.get("accept", "")
    index_html = os.path.join(FRONTEND_DIST, "index.html")
    if "text/html" in accept and "application/json" not in accept and os.path.isfile(index_html):
        return FileResponse(index_html)

    current_user = get_current_user_from_request(request, db)
    cases = db.query(Case).filter(Case.user_id == current_user.id).all()
    return cases


# ============================================================
# GET SINGLE CASE
# ============================================================

@app.get("/cases/{case_id}")
def get_case(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return get_user_case(case_id, db, current_user)


# ============================================================
# UPDATE CASE
# ============================================================

@app.put("/cases/{case_id}")
def update_case(
    case_id: str,
    case_data: CaseUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    case = get_user_case(case_id, db, current_user)

    if case_data.case_name is not None:
        case.case_name = case_data.case_name
    if case_data.investigator is not None:
        case.investigator = case_data.investigator
    if case_data.description is not None:
        case.description = case_data.description
    if case_data.status is not None:
        case.status = case_data.status

    db.commit()
    db.refresh(case)

    return {
        "message": "Case updated successfully",
        "case": case
    }


# ============================================================
# DELETE CASE
# ============================================================

@app.delete("/cases/{case_id}")
def delete_case(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    case = get_user_case(case_id, db, current_user)

    # Cascading removal of associated evidence and analysis results for this case
    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    for ev in evidence_items:
        db.query(AnalysisResult).filter(AnalysisResult.evidence_id == ev.evidence_id).delete()
        db.delete(ev)

    db.delete(case)
    db.commit()

    return {
        "message": "Case deleted successfully",
        "case_id": case_id
    }

# ============================================================
# UPLOAD EVIDENCE
# DYNAMIC EVIDENCE ID
# ============================================================

@app.post("/evidence/upload")
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Strictly verify that current_user owns the target case
    case = get_user_case(case_id, db, current_user)

    # --------------------------------------------------------
    # GENERATE EVIDENCE ID
    # --------------------------------------------------------

    evidence_id = generate_next_evidence_id(db)

    # --------------------------------------------------------
    # CREATE EVIDENCE DIRECTORY
    # --------------------------------------------------------

    evidence_directory = os.path.join(
        PROJECT_ROOT,
        "evidence"
    )

    os.makedirs(
        evidence_directory,
        exist_ok=True
    )

    # --------------------------------------------------------
    # ORIGINAL FILE NAME
    # --------------------------------------------------------

    original_filename = os.path.basename(
        file.filename
    )

    # --------------------------------------------------------
    # UNIQUE STORED FILE NAME
    # --------------------------------------------------------

    stored_filename = (
        f"{evidence_id}_{original_filename}"
    )

    file_path = os.path.join(
        evidence_directory,
        stored_filename
    )

    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    sha256_hash = hashlib.sha256()

    file_size = 0

    with open(
        file_path,
        "wb"
    ) as output_file:

        while True:

            chunk = await file.read(
                1024 * 1024
            )

            if not chunk:
                break

            output_file.write(chunk)

            sha256_hash.update(chunk)

            file_size += len(chunk)

    final_hash = sha256_hash.hexdigest()

    # --------------------------------------------------------
    # CREATE DATABASE RECORD
    # --------------------------------------------------------

    new_evidence = Evidence(
        evidence_id=evidence_id,
        case_id=case_id,
        filename=original_filename,
        file_path=file_path,
        file_size=str(file_size),
        sha256=final_hash,
        evidence_type="Memory Image",
        status="Verified"
    )

    db.add(new_evidence)

    db.commit()

    db.refresh(new_evidence)

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return {

        "message":
            "Evidence uploaded successfully",

        "evidence_id":
            evidence_id,

        "case_id":
            case_id,

        "filename":
            original_filename,

        "stored_filename":
            stored_filename,

        "size_bytes":
            file_size,

        "sha256":
            final_hash,

        "status":
            "Verified"
    }

# ============================================================
# GET ALL EVIDENCE
# ============================================================

@app.get("/evidence")
def get_all_evidence(
    request: Request,
    db: Session = Depends(get_db)
):
    accept = request.headers.get("accept", "")
    index_html = os.path.join(FRONTEND_DIST, "index.html")
    if "text/html" in accept and "application/json" not in accept and os.path.isfile(index_html):
        return FileResponse(index_html)

    current_user = get_current_user_from_request(request, db)
    user_case_ids = [c.case_id for c in db.query(Case.case_id).filter(Case.user_id == current_user.id).all()]
    if not user_case_ids:
        return []

    evidence = db.query(Evidence).filter(Evidence.case_id.in_(user_case_ids)).all()
    return evidence


# ============================================================
# GET SINGLE EVIDENCE
# ============================================================

@app.get("/evidence/{evidence_id}")
def get_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    evidence, case = get_user_evidence(evidence_id, db, current_user)
    return evidence


# ============================================================
# RESOLVE EVIDENCE FILE PATH
# ============================================================

def resolve_evidence_file_path(evidence: Evidence) -> str:
    """
    Dynamically locate the evidence file on disk across local and cloud environments.
    """
    if evidence.file_path and os.path.isfile(evidence.file_path):
        return evidence.file_path

    candidates = [
        os.path.join(PROJECT_ROOT, "evidence", os.path.basename(evidence.file_path or "")),
        os.path.join(PROJECT_ROOT, "evidence", f"{evidence.evidence_id}_{evidence.filename}"),
        os.path.join(PROJECT_ROOT, "evidence", evidence.filename),
        os.path.join(PROJECT_ROOT, "backend", "evidence", os.path.basename(evidence.file_path or "")),
        os.path.join(PROJECT_ROOT, "backend", "evidence", f"{evidence.evidence_id}_{evidence.filename}"),
        os.path.join(PROJECT_ROOT, "backend", "evidence", evidence.filename),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return evidence.file_path or ""


# ============================================================
# VERIFY EVIDENCE SHA-256
# ============================================================

@app.get("/evidence/{evidence_id}/verify")
def verify_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    resolved_path = resolve_evidence_file_path(evidence)

    if not os.path.exists(resolved_path):

        return {

            "evidence_id":
                evidence_id,

            "status":
                "ERROR",

            "message":
                f"Evidence file not found on disk: {evidence.filename}"
        }

    # Calculate hash
    sha256_hash = hashlib.sha256()

    with open(
        resolved_path,
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            sha256_hash.update(
                chunk
            )

    current_hash = sha256_hash.hexdigest()

    if current_hash == evidence.sha256:

        return {

            "evidence_id":
                evidence_id,

            "status":
                "VERIFIED",

            "stored_hash":
                evidence.sha256,

            "current_hash":
                current_hash,

            "integrity":
                "INTACT"
        }

    else:

        return {

            "evidence_id":
                evidence_id,

            "status":
                "FAILED",

            "stored_hash":
                evidence.sha256,

            "current_hash":
                current_hash,

            "integrity":
                "MODIFIED"
        }


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.get("/dashboard/statistics")
def get_dashboard_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Retrieve only cases belonging to the authenticated user
    user_cases = db.query(Case).filter(Case.user_id == current_user.id).all()
    user_case_ids = [c.case_id for c in user_cases]
    total_cases = len(user_cases)

    # Empty state for new user with zero cases
    if total_cases == 0:
        return {
            "total_cases": 0,
            "total_evidence": 0,
            "verified_evidence": 0,
            "analyses_completed": 0,
            "yara_matches": 0,
            "suspicious_events": 0,
            "high_risk_findings": 0,
            "open_investigations": 0
        }

    # Retrieve only evidence belonging to the user's cases
    user_evidence = db.query(Evidence).filter(Evidence.case_id.in_(user_case_ids)).all()
    total_evidence = len(user_evidence)
    verified_evidence = sum(1 for e in user_evidence if e.status == "Verified")
    open_investigations = sum(1 for c in user_cases if c.status in ["Open", "In Progress"])
    user_evidence_ids = [e.evidence_id for e in user_evidence]

    if not user_evidence_ids:
        return {
            "total_cases": total_cases,
            "total_evidence": 0,
            "verified_evidence": 0,
            "analyses_completed": 0,
            "yara_matches": 0,
            "suspicious_events": 0,
            "high_risk_findings": 0,
            "open_investigations": open_investigations
        }

    # Retrieve only completed analysis records for the user's evidence
    completed_analysis_records = db.query(AnalysisResult).filter(
        AnalysisResult.analysis_type == "complete",
        AnalysisResult.evidence_id.in_(user_evidence_ids)
    ).all()

    analyzed_evidence_ids = {r.evidence_id for r in completed_analysis_records}
    analyses_completed = len(analyzed_evidence_ids)

    yara_matches = 0
    suspicious_events = 0
    high_risk_findings = 0

    for record in completed_analysis_records:
        try:
            result_data = json.loads(record.result)
            yara_data = result_data.get("yara", {})
            yara_matches += int(yara_data.get("match_count", 0))

            analyzed_events = result_data.get("analyzed_events", [])
            for event in analyzed_events:
                rule_score = float(event.get("rule_score", 0) or 0)
                if rule_score > 0:
                    suspicious_events += 1

            risk_data = result_data.get("risk", {})
            risk_level = str(risk_data.get("risk_level", "")).upper()
            if risk_level in ["HIGH", "CRITICAL"]:
                high_risk_findings += 1
        except Exception:
            continue

    return {
        "total_cases": total_cases,
        "total_evidence": total_evidence,
        "verified_evidence": verified_evidence,
        "analyses_completed": analyses_completed,
        "yara_matches": yara_matches,
        "suspicious_events": suspicious_events,
        "high_risk_findings": high_risk_findings,
        "open_investigations": open_investigations
    }


# ============================================================
# SINGLE VOLATILITY ANALYSIS
# ============================================================

@app.post("/analysis/{evidence_id}")
def analyze_single_memory(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    if not os.path.exists(
        evidence.file_path
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                f"Evidence file not found: "
                f"{evidence.file_path}"
            )
        )

    command = [

        VOLATILITY_PATH,

        "-f",

        evidence.file_path,

        "windows.pslist"
    ]

    result = subprocess.run(

        command,

        capture_output=True,

        text=True
    )

    return {

        "evidence_id":
            evidence.evidence_id,

        "filename":
            evidence.filename,

        "sha256":
            evidence.sha256,

        "analysis":
            "windows.pslist",

        "return_code":
            result.returncode,

        "stdout":
            result.stdout,

        "stderr":
            result.stderr
    }


# ============================================================
# VOLATILITY ANALYSIS STATUS
# ============================================================

@app.get("/analysis/status/{evidence_id}")
def get_analysis_status(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    plugins = {

        "windows.pslist":
            "Not Run",

        "windows.pstree":
            "Not Run",

        "windows.psscan":
            "Not Run",

        "windows.netscan":
            "Not Run"
    }

    analysis_record = (

        db.query(AnalysisResult)

        .filter(

            AnalysisResult.evidence_id == evidence_id,

            AnalysisResult.analysis_type == "complete"

        )

        .order_by(

            AnalysisResult.id.desc()

        )

        .first()
    )

    if not analysis_record:

        return {

            "evidence_id":
                evidence.evidence_id,

            "filename":
                evidence.filename,

            "plugins":
                plugins,

            "analysis_available":
                False
        }

    try:

        result_data = json.loads(
            analysis_record.result
        )

    except Exception as e:

        return {

            "evidence_id":
                evidence.evidence_id,

            "filename":
                evidence.filename,

            "plugins":
                plugins,

            "analysis_available":
                False,

            "error":
                str(e)
        }

    raw_text = json.dumps(
        result_data
    ).lower()

    if (
        "windows.pslist" in raw_text
        or "process_detected" in raw_text
    ):

        plugins[
            "windows.pslist"
        ] = "Completed"

    if (
        "windows.pstree" in raw_text
        or "process_relationship" in raw_text
    ):

        plugins[
            "windows.pstree"
        ] = "Completed"

    if (
        "windows.psscan" in raw_text
        or "process_scan" in raw_text
    ):

        plugins[
            "windows.psscan"
        ] = "Completed"

    if (
        "windows.netscan" in raw_text
        or "network_connection" in raw_text
    ):

        plugins[
            "windows.netscan"
        ] = "Completed"

    return {

        "evidence_id":
            evidence.evidence_id,

        "filename":
            evidence.filename,

        "plugins":
            plugins,

        "analysis_available":
            True
    }


# ============================================================
# EVIDENCE RISK AND INTEGRITY
# ============================================================

@app.get("/analysis/risk/{evidence_id}")
def get_analysis_risk(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    analysis_record = db.query(
        AnalysisResult
    ).filter(
        AnalysisResult.evidence_id == evidence_id,
        AnalysisResult.analysis_type == "complete"
    ).order_by(
        AnalysisResult.id.desc()
    ).first()

    # Analysis has not been performed yet
    if not analysis_record:

        return {

            "evidence_id":
                evidence_id,

            "filename":
                evidence.filename,

            "sha256":
                evidence.sha256,

            "integrity_status":
                evidence.status,

            "analysis_available":
                False,

            "yara_matches":
                0,

            "suspicious_events":
                0,

            "correlations":
                0,

            "rule_score":
                0,

            "risk_level":
                "NOT ANALYZED",

            "ml_prediction":
                None,

            "ml":
                None
        }

    try:

        result_data = json.loads(
            analysis_record.result
        )

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to read analysis result"
        )

    # --------------------------------------------------------
    # YARA
    # --------------------------------------------------------

    yara_data = result_data.get(
        "yara",
        {}
    )

    yara_matches = yara_data.get(
        "match_count",
        0
    )

    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    risk_data = result_data.get(
        "risk",
        {}
    )

    risk_level = risk_data.get(
        "risk_level",
        "UNKNOWN"
    )

    # --------------------------------------------------------
    # CORRELATIONS
    # --------------------------------------------------------

    correlations = result_data.get(
        "correlations",
        []
    )

    # --------------------------------------------------------
    # SUSPICIOUS EVENTS
    # --------------------------------------------------------

    analyzed_events = result_data.get(
        "analyzed_events",
        []
    )

    suspicious_events = 0

    total_rule_score = 0

    for event in analyzed_events:

        try:

            rule_score = float(
                event.get(
                    "rule_score",
                    0
                )
            )

        except Exception:

            rule_score = 0

        if rule_score > 0:

            suspicious_events += 1

        total_rule_score += rule_score

    # --------------------------------------------------------
    # ML PREDICTION
    # --------------------------------------------------------

    ml_prediction = result_data.get(
        "ml",
        result_data.get(
            "ml_prediction",
            None
        )
    )

    # --------------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------------

    return {

        "evidence_id":
            evidence_id,

        "filename":
            evidence.filename,

        "sha256":
            evidence.sha256,

        "integrity_status":
            evidence.status,

        "analysis_available":
            True,

        "yara_matches":
            yara_matches,

        "suspicious_events":
            suspicious_events,

        "correlations":
            len(correlations),

        "rule_score":
            total_rule_score,

        "risk_level":
            risk_level,

        "ml_prediction":
            ml_prediction,

        "ml":
            ml_prediction
    }


# ============================================================
# SAVE ANALYSIS RESULT
# ============================================================

def save_analysis_result(
    db: Session,
    evidence_id: str,
    analysis_type: str,
    result_data
):

    result_text = json.dumps(
        result_data,
        default=str
    )

    analysis_result = AnalysisResult(

        evidence_id=evidence_id,

        analysis_type=analysis_type,

        result=result_text
    )

    db.add(
        analysis_result
    )

    db.commit()

    db.refresh(
        analysis_result
    )

    return analysis_result


# ============================================================
# FULL FORENSIC ANALYSIS PIPELINE
# ============================================================

@app.post("/analysis/full/{evidence_id}")
def full_memory_analysis(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # --------------------------------------------------------
    # 1. FIND EVIDENCE & VERIFY OWNERSHIP
    # --------------------------------------------------------
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    # --------------------------------------------------------
    # 2. CHECK FILE & RESOLVE PATH
    # --------------------------------------------------------

    resolved_path = resolve_evidence_file_path(evidence)

    if not os.path.exists(resolved_path):

        raise HTTPException(
            status_code=404,
            detail=(
                f"Evidence file not found on disk: {evidence.filename}. "
                f"For local analysis, please verify the file exists in the evidence folder."
            )
        )

    # --------------------------------------------------------
    # 3. VERIFY INTEGRITY BEFORE ANALYSIS
    # --------------------------------------------------------

    sha256_hash = hashlib.sha256()

    with open(
        resolved_path,
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            sha256_hash.update(
                chunk
            )

    current_hash = sha256_hash.hexdigest()

    if current_hash != evidence.sha256:

        raise HTTPException(
            status_code=409,
            detail=(
                "Evidence integrity verification failed. "
                "The evidence file may have been modified."
            )
        )

    # --------------------------------------------------------
    # 4. RUN VOLATILITY
    # --------------------------------------------------------

    print(
        "\n======================================"
    )

    print(
        "FORENSIRANSOM AI"
    )

    print(
        "FULL MEMORY FORENSIC ANALYSIS"
    )

    print(
        "======================================"
    )

    print(
        f"\nEvidence ID: {evidence_id}"
    )

    print(
        f"Evidence File: {evidence.filename}"
    )

    print(
        "\nRunning Volatility analysis..."
    )

    volatility_results = analyze_memory(
        resolved_path
    )

    # --------------------------------------------------------
    # 5. SAVE VOLATILITY RESULTS
    # --------------------------------------------------------

    save_analysis_result(

        db=db,

        evidence_id=evidence_id,

        analysis_type="volatility",

        result_data=volatility_results
    )

    # --------------------------------------------------------
    # 6. CREATE ANALYSIS RESULTS DIRECTORY
    # --------------------------------------------------------

    analysis_folder = os.path.join(
        PROJECT_ROOT,
        "analysis_results"
    )

    os.makedirs(
        analysis_folder,
        exist_ok=True
    )

    # --------------------------------------------------------
    # 7. SAVE RAW VOLATILITY OUTPUT
    # --------------------------------------------------------
    # --------------------------------------------------------
# 7. SAVE RAW VOLATILITY OUTPUT
# --------------------------------------------------------

    for name, result in volatility_results.get(
        "plugins",
        {}
    ).items():

        output_file = os.path.join(
            analysis_folder,
            f"{evidence_id}_{name}.txt"
        )

        if result.get("success"):
            with open(
                output_file,
                "w",
                encoding="utf-8",
                errors="ignore"
            ) as file:
                file.write(
                    result.get(
                        "raw_output",
                        ""
                    )
                )

    # --------------------------------------------------------
    # 8. PARSE FORENSIC RESULTS
    # --------------------------------------------------------

    print(
        "\nParsing forensic results..."
    )

    events = parse_all_results(
        evidence_id,
        raw_results_dict=volatility_results.get("plugins", {})
    )

    print(
        f"Parsed events: {len(events)}"
    )

    # --------------------------------------------------------
    # 9. BUILD TIMELINE
    # --------------------------------------------------------

    print(
        "\nBuilding forensic timeline..."
    )

    timeline = build_timeline(
        events
    )

    print(
        f"Timeline events: {len(timeline)}"
    )

    # --------------------------------------------------------
    # 10. RULE ANALYSIS
    # --------------------------------------------------------

    print(
        "\nRunning rule-based detection..."
    )

    analyzed_events = analyze_timeline(
        timeline
    )

    print(
        f"Analyzed events: {len(analyzed_events)}"
    )

    # --------------------------------------------------------
    # 10A. YARA ANALYSIS
    # --------------------------------------------------------

    print(
        "\nRunning YARA-based detection..."
    )

    yara_match_count = 0

    yara_findings = []

    for event in analyzed_events:

        raw_data = event.get(
            "evidence",
            {}
        ).get(
            "raw_data",
            ""
        )

        yara_matches = scan_text(
            raw_data
        )

        event[
            "yara_matches"
        ] = yara_matches

        if yara_matches:

            yara_match_count += len(
                yara_matches
            )

            for match in yara_matches:

                yara_findings.append({

                    "rule":
                        match.get(
                            "rule",
                            "Unknown"
                        ),

                    "event_type":
                        event.get(
                            "event_type",
                            "Unknown"
                        ),

                    "source":
                        event.get(
                            "source",
                            "Unknown"
                        ),

                    "raw_data":
                        raw_data
                })

    print(
        f"YARA matches: {yara_match_count}"
    )

    print(
        f"YARA findings collected: "
        f"{len(yara_findings)}"
    )

    # --------------------------------------------------------
    # 11. CORRELATION
    # --------------------------------------------------------

    print(
        "\nRunning evidence correlation..."
    )

    correlations = correlate_events(
        analyzed_events
    )

    print(
        f"Correlations: {len(correlations)}"
    )

    # --------------------------------------------------------
    # 12. FEATURE EXTRACTION
    # --------------------------------------------------------

    print(
        "\nExtracting forensic features..."
    )

    # First extract the forensic features that are available
    # before ML prediction. YARA findings are included here
    # so the risk engine can use them later.
    features = extract_features(
        analyzed_events,
        correlations,
        yara_findings,
        None
    )

    print(
        "Forensic features extracted successfully."
    )

    # --------------------------------------------------------
    # 12A. PREPARE ML FEATURE VECTOR
    # --------------------------------------------------------

    # The ML model was built around the original numerical
    # forensic feature set. Keep the ML input limited to those
    # numerical features so additional YARA/ML metadata used
    # by the dynamic risk engine does not break the model.
    ml_feature_keys = [
        "total_events",
        "process_events",
        "process_scan_events",
        "network_events",
        "command_events",
        "relationship_events",
        "suspicious_events",
        "high_risk_events",
        "medium_risk_events",
        "powershell_events",
        "encoded_command_events",
        "suspicious_tool_events",
        "total_rule_score",
        "maximum_rule_score",
        "correlation_count",
        "high_severity_correlations",
        "medium_severity_correlations",
        "suspicious_event_ratio"
    ]

    ml_features = {
        key: features.get(key, 0)
        for key in ml_feature_keys
    }

    # --------------------------------------------------------
    # 12B. ML PREDICTION
    # --------------------------------------------------------

    print(
        "\nRunning ML prediction..."
    )

    try:

        ml_prediction = predict(
            ml_features
        )

        print(
            "ML Classification:",
            ml_prediction.get(
                "classification",
                "Unknown"
            )
        )

        print(
            "ML Probabilities:",
            ml_prediction.get(
                "probabilities",
                {}
            )
        )

    except Exception as e:

        print(
            "ML prediction failed:",
            str(e)
        )

        ml_prediction = {

            "prediction":
                None,

            "classification":
                "Unavailable",

            "probabilities":
                {},

            "error":
                str(e)
        }

    # --------------------------------------------------------
    # 12C. UPDATE FEATURES WITH ML RESULTS
    # --------------------------------------------------------

    print(
        "\nUpdating forensic features with ML results..."
    )

    # Re-extract the complete evidence-specific feature set.
    # This time the ML probabilities are available and can be
    # consumed by the dynamic risk engine.
    features = extract_features(
        analyzed_events,
        correlations,
        yara_findings,
        ml_prediction
    )

    print(
        "ML-aware forensic features prepared."
    )

    # --------------------------------------------------------
    # 12D. ML DATASET STATUS
    # --------------------------------------------------------

    print(
        "\nPreparing ML dataset..."
    )

    print(
        "Forensic features extracted successfully."
    )

    print(
        "ML prediction completed."
    )

    # --------------------------------------------------------
    # 13. DYNAMIC RISK ASSESSMENT
    # --------------------------------------------------------

    print(
        "\nCalculating evidence-specific forensic risk..."
    )

    # Risk is calculated from the CURRENT evidence analysis.
    # It is not a fixed value and is not copied from the ML
    # classification alone.
    risk = calculate_risk_score(
        features
    )

    print(
        "Risk Score:",
        risk.get(
            "risk_score",
            0
        )
    )

    print(
        "Risk Level:",
        risk.get(
            "risk_level",
            "UNKNOWN"
        )
    )

    # --------------------------------------------------------
    # 14. SAVE TIMELINE
    # --------------------------------------------------------

    save_analysis_result(

        db=db,

        evidence_id=evidence_id,

        analysis_type="timeline",

        result_data=timeline
    )

    # --------------------------------------------------------
    # 15. SAVE CORRELATIONS
    # --------------------------------------------------------

    save_analysis_result(

        db=db,

        evidence_id=evidence_id,

        analysis_type="correlation",

        result_data=correlations
    )

    # --------------------------------------------------------
    # 16. SAVE FEATURES
    # --------------------------------------------------------

    save_analysis_result(

        db=db,

        evidence_id=evidence_id,

        analysis_type="features",

        result_data=features
    )

    # --------------------------------------------------------
    # 17. SAVE RISK
    # --------------------------------------------------------

    save_analysis_result(

        db=db,

        evidence_id=evidence_id,

        analysis_type="risk",

        result_data=risk
    )

    # --------------------------------------------------------
    # 18. COMPLETE PIPELINE RESULT
    # --------------------------------------------------------

    case_data = db.query(
        Case
    ).filter(
        Case.case_id == evidence.case_id
    ).first()

    complete_result = {
    "case": {
        "case_id": case_data.case_id if case_data else evidence.case_id,
        "case_name": case_data.case_name if case_data else "Case information unavailable",
        "investigator": case_data.investigator if case_data else "Investigator information unavailable",
        "description": case_data.description if case_data else None,
        "status": case_data.status if case_data else "Unknown"
    },

    "evidence": {
        "evidence_id": evidence.evidence_id,
        "case_id": evidence.case_id,
        "filename": evidence.filename,
        "sha256": evidence.sha256,
        "integrity": "INTACT",
        "status": evidence.status
    },

        # --------------------------------------------
        # VOLATILITY
        # --------------------------------------------
"volatility": {
    "status": (
        "COMPLETED"
        if volatility_results.get(
            "successful_plugins",
            0
        ) > 0
        else "FAILED"
    ),

    "memory_path": volatility_results.get(
        "memory_path"
    ),

    "total_plugins": volatility_results.get(
        "total_plugins",
        0
    ),

    "successful_plugins": volatility_results.get(
        "successful_plugins",
        0
    ),

    "failed_plugins": volatility_results.get(
        "failed_plugins",
        0
    ),

    "plugins": {
        name: (
            "Completed"
            if result.get("success")
            else "Failed"
        )
        for name, result
        in volatility_results.get(
            "plugins",
            {}
        ).items()
    }
},

        # --------------------------------------------
        # FORENSIC SUMMARY
        # --------------------------------------------

        "forensics": {

            "parsed_events":
                len(events),

            "timeline_events":
                len(timeline),

            "analyzed_events":
                len(analyzed_events),

            "correlations":
                len(correlations),

            "timeline":
                timeline,

            "correlation_findings":
                correlations
        },

        # --------------------------------------------
        # TIMELINE
        # --------------------------------------------

        "timeline":
            timeline,

        # --------------------------------------------
        # ANALYZED EVENTS
        # --------------------------------------------

        "analyzed_events":
            analyzed_events,

        # --------------------------------------------
        # CORRELATIONS
        # --------------------------------------------

        "correlations":
            correlations,

        # --------------------------------------------
        # FEATURES
        # --------------------------------------------

        "features":
            features,

        # --------------------------------------------
        # ML PREDICTION
        # --------------------------------------------

        "ml":
            ml_prediction,

        # Keep this for backward compatibility
        "ml_prediction":
            ml_prediction,

        # --------------------------------------------
        # RISK
        # --------------------------------------------

        "risk":
            risk,

        # --------------------------------------------
        # YARA
        # --------------------------------------------

        "yara": {

            "match_count":
                yara_match_count,

            "findings":
                yara_findings
        }
    }

    # --------------------------------------------------------
    # SAVE COMPLETE RESULT
    # --------------------------------------------------------

    save_analysis_result(

        db=db,

        evidence_id=evidence_id,

        analysis_type="complete",

        result_data=complete_result
    )

    # --------------------------------------------------------
    # 19. RETURN COMPLETE RESULT
    # --------------------------------------------------------

    print(
        "\n======================================"
    )

    print(
        "FULL FORENSIC ANALYSIS COMPLETED"
    )

    print(
        "======================================"
    )

    return {

        "message":
            "Full forensic analysis completed",

        "evidence_id":
            evidence_id,

        "filename":
            evidence.filename,

        "sha256":
            evidence.sha256,

        "integrity":
            "INTACT",

        "volatility":
            volatility_results,

        "parsed_events":
            len(events),

        "timeline":
            timeline,

        "analyzed_events":
            analyzed_events,

        "correlations":
            correlations,

        "features":
            features,

        "ml":
            ml_prediction,

        # Backward compatibility
        "ml_prediction":
            ml_prediction,

        "risk":
            risk,

        "yara": {

            "match_count":
                yara_match_count,

            "findings":
                yara_findings
        }
    }


# ============================================================
# GET STORED ANALYSIS RESULTS
# ============================================================

@app.get("/analysis/results/{evidence_id}")
def get_analysis_results(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Strictly verify ownership
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    # --------------------------------------------------------
    # GET LATEST COMPLETE ANALYSIS
    # --------------------------------------------------------

    complete_record = db.query(
        AnalysisResult
    ).filter(

        AnalysisResult.evidence_id == evidence_id,

        AnalysisResult.analysis_type == "complete"

    ).order_by(

        AnalysisResult.created_at.desc()

    ).first()

    if not complete_record:

        raise HTTPException(

            status_code=404,

            detail=(
                "No complete analysis found. "
                "Run Full Analysis first."
            )
        )

    # --------------------------------------------------------
    # PARSE STORED RESULT
    # --------------------------------------------------------

    try:

        complete_result = json.loads(
            complete_record.result
        )

    except Exception:

        raise HTTPException(

            status_code=500,

            detail="Stored analysis result is invalid."
        )

    if not isinstance(
        complete_result,
        dict
    ):

        raise HTTPException(

            status_code=500,

            detail="Stored analysis result is invalid."
        )

    # --------------------------------------------------------
    # NORMALIZE CASE
    # --------------------------------------------------------

    case_data = db.query(
        Case
    ).filter(
        Case.case_id == evidence.case_id
    ).first()

    complete_result["case"] = {
        "case_id": case_data.case_id if case_data else evidence.case_id,
        "case_name": case_data.case_name if case_data else "Case information unavailable",
        "investigator": case_data.investigator if case_data else "Investigator information unavailable",
        "description": case_data.description if case_data else None,
        "status": case_data.status if case_data else "Unknown"
    }

    # --------------------------------------------------------
    # NORMALIZE EVIDENCE
    # --------------------------------------------------------

    complete_result["evidence"] = {
    "evidence_id": evidence.evidence_id,
    "case_id": evidence.case_id,
    "filename": evidence.filename,
    "sha256": evidence.sha256,
    "integrity": "INTACT",
    "status": evidence.status
}

    # --------------------------------------------------------
    # NORMALIZE ML
    # --------------------------------------------------------

    if (
        "ml" not in complete_result
        and
        "ml_prediction" in complete_result
    ):

        complete_result["ml"] = (
            complete_result["ml_prediction"]
        )

    if "ml" not in complete_result:

        complete_result["ml"] = {

            "prediction":
                None,

            "classification":
                "NOT AVAILABLE",

            "probabilities": {

                "Normal":
                    0,

                "Suspicious":
                    0,

                "Ransomware":
                    0
            }
        }

    # --------------------------------------------------------
    # NORMALIZE FORENSIC SUMMARY
    # --------------------------------------------------------

    if "forensics" not in complete_result:

        complete_result["forensics"] = {

            "parsed_events":
                len(
                    complete_result.get(
                        "timeline",
                        []
                    )
                ),

            "timeline_events":
                len(
                    complete_result.get(
                        "timeline",
                        []
                    )
                ),

            "analyzed_events":
                len(
                    complete_result.get(
                        "analyzed_events",
                        []
                    )
                ),

            "correlations":
                len(
                    complete_result.get(
                        "correlations",
                        []
                    )
                )
        }

    # --------------------------------------------------------
    # NORMALIZE YARA
    # --------------------------------------------------------

    if "yara" not in complete_result:

        complete_result["yara"] = {

            "match_count":
                0,

            "findings":
                []
        }

    # --------------------------------------------------------
    # NORMALIZE CORRELATIONS
    # --------------------------------------------------------

    if "correlations" not in complete_result:

        complete_result["correlations"] = []

    # --------------------------------------------------------
    # NORMALIZE TIMELINE
    # --------------------------------------------------------

    if "timeline" not in complete_result:

        complete_result["timeline"] = []

    # --------------------------------------------------------
    # NORMALIZE ANALYZED EVENTS
    # --------------------------------------------------------

    if "analyzed_events" not in complete_result:

        complete_result["analyzed_events"] = []

    # --------------------------------------------------------
    # NORMALIZE VOLATILITY
    # --------------------------------------------------------

    if "volatility" not in complete_result:

        complete_result["volatility"] = {

            "status":
                "NOT AVAILABLE",

            "plugins": {}
        }

    else:

        volatility_data = complete_result[
            "volatility"
        ]

        if "plugins" not in volatility_data:

            volatility_data["plugins"] = {}

    # --------------------------------------------------------
    # RETURN UNIFIED ANALYSIS RESULT
    # --------------------------------------------------------

    return complete_result


# ============================================================
# DELETE EVIDENCE
# ============================================================

@app.delete("/evidence/{evidence_id}")
def delete_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    # Delete physical file
    if os.path.exists(
        evidence.file_path
    ):

        os.remove(
            evidence.file_path
        )

    # Delete analysis records
    analysis_records = db.query(
        AnalysisResult
    ).filter(
        AnalysisResult.evidence_id == evidence_id
    ).all()

    for record in analysis_records:

        db.delete(
            record
        )

    # Delete evidence
    db.delete(
        evidence
    )

    db.commit()

    return {
        "message":
            "Evidence and analysis results deleted successfully",
        "evidence_id":
            evidence_id
    }


# ============================================================
# REPORTS & GEMINI AI FORENSIC RECOMMENDATIONS
# ============================================================

def _load_report_evidence_and_analysis(evidence_id: str, db: Session, current_user: User) -> dict:
    """
    Helper to safely retrieve evidence, case metadata, and complete analysis,
    strictly verifying that the authenticated user owns the parent case.
    """
    evidence, case = get_user_evidence(evidence_id, db, current_user)

    complete_record = db.query(AnalysisResult).filter(
        AnalysisResult.evidence_id == evidence_id,
        AnalysisResult.analysis_type == "complete"
    ).order_by(
        AnalysisResult.created_at.desc()
    ).first()

    if complete_record:
        try:
            complete_result = json.loads(complete_record.result)
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Stored analysis result contains invalid JSON."
            )
    else:
        # Check if individual sub-analysis records exist for partial reporting
        sub_records = db.query(AnalysisResult).filter(
            AnalysisResult.evidence_id == evidence_id
        ).all()
        if not sub_records:
            raise HTTPException(
                status_code=404,
                detail=f"No forensic analysis records found for evidence {evidence_id}. Please run analysis on the Analysis page first."
            )
        complete_result = {
            "evidence": {
                "evidence_id": evidence.evidence_id,
                "case_id": evidence.case_id,
                "filename": evidence.filename,
                "sha256": evidence.sha256,
                "status": evidence.status,
                "integrity": "INTACT"
            },
            "volatility": {"status": "PARTIAL", "plugins": {}},
            "forensics": {},
            "timeline": [],
            "analyzed_events": [],
            "correlations": [],
            "features": {},
            "ml": {"classification": "Normal", "probabilities": {}},
            "risk": {"risk_score": 0, "risk_level": "LOW", "reasons": []},
            "yara": {"match_count": 0, "findings": []}
        }
        for rec in sub_records:
            try:
                p_val = json.loads(rec.result)
                if rec.analysis_type == "volatility":
                    complete_result["volatility"] = p_val
                elif rec.analysis_type == "timeline":
                    complete_result["timeline"] = p_val
                elif rec.analysis_type == "correlation":
                    complete_result["correlations"] = p_val
                elif rec.analysis_type == "features":
                    complete_result["features"] = p_val
                elif rec.analysis_type == "risk":
                    complete_result["risk"] = p_val
            except Exception:
                pass

    complete_result["case"] = {
        "case_id": case.case_id,
        "case_name": case.case_name or "Forensic Investigation",
        "investigator": case.investigator or current_user.username,
        "description": case.description or "",
        "status": case.status or "Open"
    }

    complete_result["evidence"] = {
        "evidence_id": evidence.evidence_id,
        "case_id": evidence.case_id,
        "filename": evidence.filename,
        "file_path": evidence.file_path,
        "file_size": evidence.file_size,
        "sha256": evidence.sha256,
        "evidence_type": evidence.evidence_type,
        "status": evidence.status,
        "created_at": str(evidence.created_at)
    }

    return complete_result


@app.get("/reports/recommendations/{evidence_id}")
@app.post("/reports/recommendations/{evidence_id}")
def get_report_recommendations(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Generates AI-powered forensic investigation recommendations for the selected evidence.
    Uses Google Gemini when GEMINI_API_KEY is configured; seamlessly falls back
    to the offline Forensic Rule Engine when Gemini is not configured or unavailable.
    """
    analysis_data = _load_report_evidence_and_analysis(evidence_id, db, current_user)
    recommendations = get_recommendations(analysis_data)
    return recommendations


@app.get("/reports/pdf/{evidence_id}")
def download_pdf_report(
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Generates and downloads a formal forensic investigation PDF report
    containing case metadata, SHA-256 verification, Volatility findings,
    YARA detections, IOCs, ML assessment, risk score, and AI recommendations.
    Strictly verifies evidence ownership for the requesting user.
    """
    current_user = get_current_user_from_request(request, db)
    analysis_data = _load_report_evidence_and_analysis(evidence_id, db, current_user)
    pdf_bytes = generate_pdf_report(analysis_data)
    
    case_id = analysis_data.get("case", {}).get("case_id", "FRA")
    filename = f"Forensic_Report_{case_id}_{evidence_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@app.get("/reports/json/{evidence_id}")
def export_json_report(
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Exports the comprehensive forensic investigation report in structured JSON format.
    Strictly verifies evidence ownership for the requesting user.
    """
    current_user = get_current_user_from_request(request, db)
    analysis_data = _load_report_evidence_and_analysis(evidence_id, db, current_user)
    json_report = generate_json_report(analysis_data)
    
    case_id = analysis_data.get("case", {}).get("case_id", "FRA")
    filename = f"Forensic_Report_{case_id}_{evidence_id}.json"

    return Response(
        content=json.dumps(json_report, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@app.get("/reports/evidence-log/{evidence_id}")
def export_evidence_log(
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Exports a digital evidence integrity & verification audit log in JSON format.
    Strictly verifies evidence ownership for the requesting user.
    """
    current_user = get_current_user_from_request(request, db)
    analysis_data = _load_report_evidence_and_analysis(evidence_id, db, current_user)
    log_data = generate_evidence_log(analysis_data)

    case_id = analysis_data.get("case", {}).get("case_id", "FRA")
    filename = f"Evidence_Log_{case_id}_{evidence_id}.json"

    return Response(
        content=json.dumps(log_data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


# ============================================================
# APPLICATION INFORMATION
# ============================================================

@app.get("/info")
def application_info():

    return {

        "name":
            "ForensiRansom AI",

        "version":
            "1.0.0",

        "modules": [

            "Case Management",

            "Evidence Management",

            "SHA-256 Integrity Verification",

            "Memory Acquisition",

            "Memory Forensics",

            "Volatility 3",

            "Process Analysis",

            "Network Analysis",

            "Command-Line Analysis",

            "YARA",

            "IOC Engine",

            "AI/ML",

            "Correlation Engine",

            "Feature Extraction",

            "Risk Assessment",

            "Timeline",

            "Forensic Reporting"
        ]
    }


# ============================================================
# SPA CLIENT-SIDE ROUTING & STATIC ASSETS HANDLER
# ============================================================

@app.get("/{full_path:path}")
async def serve_spa_app(full_path: str):
    candidate = os.path.join(FRONTEND_DIST, full_path)
    if os.path.isfile(candidate):
        return FileResponse(candidate)

    index_html = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.isfile(index_html):
        return FileResponse(index_html)

    raise HTTPException(status_code=404, detail="Not Found")
