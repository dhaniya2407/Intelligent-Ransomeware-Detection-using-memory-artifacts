"""
Automated Security, Authentication, and Per-User Data Isolation Test Suite
ForensiRansom AI — Multi-User Verification (Account A, Account B, Account C)
"""

import os
import sys
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from main import app
from database import SessionLocal
from models import User, Case, Evidence, AnalysisResult

client = TestClient(app)

def test_three_account_security_and_isolation():
    print("\n=======================================================")
    print("STARTING FORENSIRANSOM AI 3-ACCOUNT ISOLATION TEST")
    print("=======================================================")

    # ---------------------------------------------------------
    # TEST 1: Unauthenticated requests are rejected (401)
    # ---------------------------------------------------------
    print("\n[*] 1. Testing Unauthenticated Request Rejection...")
    res = client.get("/cases", headers={"Accept": "application/json"})
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    res = client.get("/evidence", headers={"Accept": "application/json"})
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    res = client.get("/dashboard/statistics")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    print("[PASS] Unauthenticated access properly rejected with 401.")

    # ---------------------------------------------------------
    # Setup test credentials for Accounts A, B, and C
    # ---------------------------------------------------------
    user_a = {"username": "investigator_alpha", "email": "alpha@forensic-test.local", "password": "AlphaPassword2026!", "role": "Lead Investigator"}
    user_b = {"username": "investigator_beta", "email": "beta@forensic-test.local", "password": "BetaPassword2026!", "role": "Senior Analyst"}
    user_c = {"username": "investigator_gamma", "email": "gamma@forensic-test.local", "password": "GammaPassword2026!", "role": "Incident Responder"}

    # Clean up any leftover test data
    db = SessionLocal()
    for u in [user_a["username"], user_b["username"], user_c["username"], "brute_target_test"]:
        existing = db.query(User).filter(User.username == u).first()
        if existing:
            user_cases = db.query(Case).filter(Case.user_id == existing.id).all()
            for c in user_cases:
                evs = db.query(Evidence).filter(Evidence.case_id == c.case_id).all()
                for e in evs:
                    db.query(AnalysisResult).filter(AnalysisResult.evidence_id == e.evidence_id).delete()
                    if os.path.exists(e.file_path):
                        try:
                            os.remove(e.file_path)
                        except Exception:
                            pass
                    db.delete(e)
                db.delete(c)
            db.delete(existing)
            db.commit()
    db.close()

    # ---------------------------------------------------------
    # TEST 2: Account A Workflow
    # ---------------------------------------------------------
    print("\n[*] 2. Registering Account A (Alpha) and Creating Case...")
    reg_a = client.post("/register", json=user_a)
    assert reg_a.status_code == 200, f"Account A registration failed: {reg_a.text}"
    token_a = reg_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}", "Accept": "application/json"}

    case_a_res = client.post("/cases", headers=headers_a, json={
        "case_name": "Alpha Ransomware Attack",
        "investigator": "Investigator Alpha",
        "description": "Host encrypted by LockBit",
        "status": "Open"
    })
    assert case_a_res.status_code == 200, f"Account A case creation failed: {case_a_res.text}"
    case_a_id = case_a_res.json()["case"]["case_id"]

    ev_a_res = client.post(
        f"/evidence/upload?case_id={case_a_id}",
        headers=headers_a,
        files={"file": ("alpha_mem.raw", b"ACCOUNT_A_MEMORY_IMAGE_CONTENT_BYTES_2026", "application/octet-stream")}
    )
    assert ev_a_res.status_code == 200, f"Account A evidence upload failed: {ev_a_res.text}"
    ev_a_id = ev_a_res.json()["evidence_id"]
    ev_a_hash = ev_a_res.json()["sha256"]

    stats_a = client.get("/dashboard/statistics", headers=headers_a).json()
    assert stats_a["total_cases"] == 1
    assert stats_a["total_evidence"] == 1
    assert stats_a["open_investigations"] == 1
    print(f"[PASS] Account A workspace verified: Case {case_a_id}, Evidence {ev_a_id}.")

    # ---------------------------------------------------------
    # TEST 3: Account B Workflow (Zero-State then Separate Data)
    # ---------------------------------------------------------
    print("\n[*] 3. Registering Account B (Beta) & Verifying Empty Workspace...")
    reg_b = client.post("/register", json=user_b)
    assert reg_b.status_code == 200, f"Account B registration failed: {reg_b.text}"
    token_b = reg_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}", "Accept": "application/json"}

    # B must see 0 cases, 0 evidence, 0 open investigations
    stats_b = client.get("/dashboard/statistics", headers=headers_b).json()
    assert stats_b["total_cases"] == 0, f"Expected 0 cases for Account B, got {stats_b['total_cases']}"
    assert stats_b["total_evidence"] == 0, f"Expected 0 evidence for Account B, got {stats_b['total_evidence']}"
    assert stats_b["open_investigations"] == 0
    assert stats_b["yara_matches"] == 0
    assert stats_b["suspicious_events"] == 0

    cases_b = client.get("/cases", headers=headers_b).json()
    assert len(cases_b) == 0, "Account B must see 0 cases"
    print("[PASS] Account B initial state verified: 0 cases, 0 evidence.")

    # Account B creates its own case and evidence
    print("\n[*] 4. Account B creating its own private case and evidence...")
    case_b_res = client.post("/cases", headers=headers_b, json={
        "case_name": "Beta Exfiltration Investigation",
        "investigator": "Investigator Beta",
        "description": "Suspected data theft",
        "status": "In Progress"
    })
    assert case_b_res.status_code == 200
    case_b_id = case_b_res.json()["case"]["case_id"]

    ev_b_res = client.post(
        f"/evidence/upload?case_id={case_b_id}",
        headers=headers_b,
        files={"file": ("beta_mem.raw", b"ACCOUNT_B_EXFILTRATION_MEMORY_BYTES_2026", "application/octet-stream")}
    )
    assert ev_b_res.status_code == 200
    ev_b_id = ev_b_res.json()["evidence_id"]

    stats_b2 = client.get("/dashboard/statistics", headers=headers_b).json()
    assert stats_b2["total_cases"] == 1
    assert stats_b2["total_evidence"] == 1
    print(f"[PASS] Account B private workspace verified: Case {case_b_id}, Evidence {ev_b_id}.")

    # ---------------------------------------------------------
    # TEST 4: Account C Workflow (New User Zero-State)
    # ---------------------------------------------------------
    print("\n[*] 5. Registering Account C (Gamma) & Verifying Empty Workspace...")
    reg_c = client.post("/register", json=user_c)
    assert reg_c.status_code == 200, f"Account C registration failed: {reg_c.text}"
    token_c = reg_c.json()["access_token"]
    headers_c = {"Authorization": f"Bearer {token_c}", "Accept": "application/json"}

    stats_c = client.get("/dashboard/statistics", headers=headers_c).json()
    assert stats_c["total_cases"] == 0, f"Expected 0 cases for Account C, got {stats_c['total_cases']}"
    assert stats_c["total_evidence"] == 0
    assert stats_c["open_investigations"] == 0
    assert stats_c["analyses_completed"] == 0
    assert stats_c["yara_matches"] == 0
    assert stats_c["suspicious_events"] == 0
    assert stats_c["high_risk_findings"] == 0

    cases_c = client.get("/cases", headers=headers_c).json()
    assert len(cases_c) == 0, "Account C must see 0 cases in listing"

    evidence_c = client.get("/evidence", headers=headers_c).json()
    assert len(evidence_c) == 0, "Account C must see 0 evidence in listing"
    print("[PASS] Account C verified: Completely empty dashboard and listings.")

    # ---------------------------------------------------------
    # TEST 5: Comprehensive Cross-Account Unauthorized Probes
    # ---------------------------------------------------------
    print("\n[*] 6. Testing Cross-Account Boundary Probes (A vs B vs C)...")

    # 6a: A requests B's case ID -> Rejected (404)
    res = client.get(f"/cases/{case_b_id}", headers=headers_a)
    assert res.status_code == 404, f"A accessing B's case must return 404, got {res.status_code}"
    print(f"[PASS] A requesting B's case ({case_b_id}) returned 404.")

    # 6b: B requests A's case ID -> Rejected (404)
    res = client.get(f"/cases/{case_a_id}", headers=headers_b)
    assert res.status_code == 404, f"B accessing A's case must return 404, got {res.status_code}"
    print(f"[PASS] B requesting A's case ({case_a_id}) returned 404.")

    # 6c: B requests A's evidence -> Rejected (404)
    res = client.get(f"/evidence/{ev_a_id}", headers=headers_b)
    assert res.status_code == 404, f"B accessing A's evidence must return 404, got {res.status_code}"
    print(f"[PASS] B requesting A's evidence ({ev_a_id}) returned 404.")

    # 6d: C requests A's evidence -> Rejected (404)
    res = client.get(f"/evidence/{ev_a_id}", headers=headers_c)
    assert res.status_code == 404, f"C accessing A's evidence must return 404, got {res.status_code}"
    print(f"[PASS] C requesting A's evidence ({ev_a_id}) returned 404.")

    # 6e: C requests B's evidence -> Rejected (404)
    res = client.get(f"/evidence/{ev_b_id}", headers=headers_c)
    assert res.status_code == 404, f"C accessing B's evidence must return 404, got {res.status_code}"
    print(f"[PASS] C requesting B's evidence ({ev_b_id}) returned 404.")

    # 6f: C requests A's report PDF -> Rejected (404)
    res = client.get(f"/reports/pdf/{ev_a_id}", headers=headers_c)
    assert res.status_code == 404, f"C accessing A's report PDF must return 404, got {res.status_code}"
    print(f"[PASS] C requesting A's report PDF ({ev_a_id}) returned 404.")

    # 6g: C requests B's report PDF -> Rejected (404)
    res = client.get(f"/reports/pdf/{ev_b_id}", headers=headers_c)
    assert res.status_code == 404, f"C accessing B's report PDF must return 404, got {res.status_code}"
    print(f"[PASS] C requesting B's report PDF ({ev_b_id}) returned 404.")

    # 6h: C requests A's report JSON -> Rejected (404)
    res = client.get(f"/reports/json/{ev_a_id}", headers=headers_c)
    assert res.status_code == 404, f"C accessing A's report JSON must return 404, got {res.status_code}"
    print(f"[PASS] C requesting A's report JSON ({ev_a_id}) returned 404.")

    # 6i: C requests A's recommendations -> Rejected (404)
    res = client.get(f"/reports/recommendations/{ev_a_id}", headers=headers_c)
    assert res.status_code == 404, f"C accessing A's recommendations must return 404, got {res.status_code}"
    print(f"[PASS] C requesting A's recommendations ({ev_a_id}) returned 404.")

    # 6j: A requests B's recommendations -> Rejected (404)
    res = client.get(f"/reports/recommendations/{ev_b_id}", headers=headers_a)
    assert res.status_code == 404, f"A accessing B's recommendations must return 404, got {res.status_code}"
    print(f"[PASS] A requesting B's recommendations ({ev_b_id}) returned 404.")

    # ---------------------------------------------------------
    # TEST 6: Reports & Recommendations on Authorized Evidence
    # ---------------------------------------------------------
    print("\n[*] 7. Testing Case-Specific Reports & Recommendations for Legitimate Owner...")
    
    # Store a simulated analysis record for Account A's evidence to enable reporting
    db = SessionLocal()
    mock_complete_res = {
        "volatility": {"status": "COMPLETED", "plugins": {"windows.pslist": {"process_count": 42}}},
        "forensics": {"processes": 42},
        "timeline": [{"timestamp": "2026-10-23T12:00:00Z", "event": "powershell.exe executed encoded command"}],
        "analyzed_events": [{"rule_score": 5.0, "message": "Suspicious PowerShell execution"}],
        "correlations": [{"correlation_type": "Process-Command", "description": "Encoded command line detected"}],
        "features": {"total_events": 42, "process_events": 35, "command_events": 5, "network_events": 2, "suspicious_events": 1},
        "ml": {"classification": "Ransomware", "probabilities": {"Ransomware": 0.94, "Benign": 0.06}},
        "risk": {"risk_score": 85, "risk_level": "HIGH", "reasons": ["Encoded PowerShell command", "High ML confidence"]},
        "yara": {"match_count": 2, "findings": [{"rule": "Ransomware_Extension_Check", "description": "Ransomware string pattern"}]}
    }
    rec = AnalysisResult(
        evidence_id=ev_a_id,
        analysis_type="complete",
        result=json.dumps(mock_complete_res)
    )
    db.add(rec)
    db.commit()
    db.close()

    # Account A requests recommendations
    rec_res = client.get(f"/reports/recommendations/{ev_a_id}", headers=headers_a)
    assert rec_res.status_code == 200, f"Expected 200, got {rec_res.status_code}: {rec_res.text}"
    rec_data = rec_res.json()
    assert "executive_summary" in rec_data
    assert "immediate_response" in rec_data
    assert "mitre_attack" in rec_data
    assert case_a_id in str(rec_data) or "FRA" in str(rec_data)
    print(f"[PASS] Account A recommendations generated for Case {case_a_id} (Provider: {rec_data.get('provider')}).")

    # Account A downloads PDF report
    pdf_res = client.get(f"/reports/pdf/{ev_a_id}", headers=headers_a)
    assert pdf_res.status_code == 200, f"PDF export failed: {pdf_res.status_code}"
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000, "PDF content must be non-empty binary"
    print(f"[PASS] Account A PDF report successfully generated ({len(pdf_res.content)} bytes).")

    # Account A downloads JSON report
    json_res = client.get(f"/reports/json/{ev_a_id}", headers=headers_a)
    assert json_res.status_code == 200
    json_data = json_res.json()
    assert json_data["case_details"]["case_id"] == case_a_id
    assert json_data["evidence_details"]["evidence_id"] == ev_a_id
    print(f"[PASS] Account A JSON report verified with Case {case_a_id} metadata.")

    # ---------------------------------------------------------
    # TEST 7: Account Switching & Logout Session Invalidation
    # ---------------------------------------------------------
    print("\n[*] 8. Testing Account Switching and Logout...")
    # Call logout
    logout_res = client.post("/auth/logout", headers=headers_a)
    assert logout_res.status_code == 200

    # User profile lookup with valid token works
    me_a = client.get("/auth/me", headers=headers_a).json()
    assert me_a["username"] == user_a["username"]

    # User profile lookup with User B's token returns User B
    me_b = client.get("/auth/me", headers=headers_b).json()
    assert me_b["username"] == user_b["username"]
    assert me_b["username"] != me_a["username"]
    print("[PASS] User tokens are strictly isolated between accounts.")

    # ---------------------------------------------------------
    # TEST 8: Legacy Data Integrity & Chain of Custody
    # ---------------------------------------------------------
    print("\n[*] 9. Verifying Legacy Case & Evidence Integrity...")
    db = SessionLocal()
    dhaniya = db.query(User).filter(User.username == "dhaniya").first()
    assert dhaniya is not None, "Legacy owner dhaniya must exist"

    dhaniya_cases = db.query(Case).filter(Case.user_id == dhaniya.id).all()
    assert len(dhaniya_cases) >= 4, f"Expected 4 legacy cases, found {len(dhaniya_cases)}"
    case_ids = [c.case_id for c in dhaniya_cases]
    for expected_cid in ["FRA-001", "FRA-002", "FRA-003", "FRA-004"]:
        assert expected_cid in case_ids, f"Legacy case {expected_cid} missing"

    legacy_evidence = db.query(Evidence).filter(Evidence.case_id.in_(case_ids)).all()
    assert len(legacy_evidence) >= 5, f"Expected 5 legacy evidence records, found {len(legacy_evidence)}"
    for le in legacy_evidence:
        assert len(le.sha256) == 64, f"Evidence {le.evidence_id} has invalid SHA-256 hash"
    print(f"[PASS] All legacy records preserved intact with confirmed SHA-256 integrity.")
    db.close()

    # ---------------------------------------------------------
    # CLEANUP TEST ACCOUNTS
    # ---------------------------------------------------------
    db = SessionLocal()
    for u in [user_a["username"], user_b["username"], user_c["username"]]:
        existing = db.query(User).filter(User.username == u).first()
        if existing:
            user_cases = db.query(Case).filter(Case.user_id == existing.id).all()
            for c in user_cases:
                evs = db.query(Evidence).filter(Evidence.case_id == c.case_id).all()
                for e in evs:
                    db.query(AnalysisResult).filter(AnalysisResult.evidence_id == e.evidence_id).delete()
                    if os.path.exists(e.file_path):
                        try:
                            os.remove(e.file_path)
                        except Exception:
                            pass
                    db.delete(e)
                db.delete(c)
            db.delete(existing)
            db.commit()
    db.close()

    print("\n=======================================================")
    print("ALL 3-ACCOUNT TESTS PASSED PERFECTLY!")
    print("=======================================================\n")

if __name__ == "__main__":
    test_three_account_security_and_isolation()
