# ============================================================
# FORENSIRANSOM AI — AUTHENTICATION & USER DATA ISOLATION ENGINE
# ============================================================
# Secure authentication, JWT token lifecycle, rate-limiting,
# and cryptographic user-data isolation for forensic investigations.
# ============================================================

import os
import time
import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Tuple

import bcrypt
from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import SessionLocal
from models import User, Case, Evidence

# Configuration
JWT_SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY",
    "forensiransom_dfir_super_secure_jwt_token_secret_key_2026_x89a42f"
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours

# In-memory brute-force rate limiter
LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 900  # 15 minutes

# Bearer security scheme (optional so custom extraction handles both headers & queries)
security_scheme = HTTPBearer(auto_error=False)


# ============================================================
# PASSWORD HASHING (BCRYPT)
# ============================================================

def hash_password(password: str) -> str:
    """Hashes a password with bcrypt and unique salt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


# ============================================================
# JWT TOKEN LIFECYCLE
# ============================================================

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ''
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates an expiring signed JWT access token.
    Uses python-jose if available, with built-in standard HMAC-SHA256 fallback.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp()), "iat": int(datetime.now(timezone.utc).timestamp())})

    try:
        from jose import jwt
        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    except Exception:
        # Standard library fallback (HS256 compliant)
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = _base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_b64 = _base64url_encode(json.dumps(to_encode, separators=(',', ':')).encode('utf-8'))
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        sig = hmac.new(JWT_SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
        sig_b64 = _base64url_encode(sig)
        return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Optional[dict]:
    """
    Decodes and validates JWT token expiration and signature.
    """
    if not token or not isinstance(token, str):
        return None

    try:
        from jose import jwt, JWTError
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        pass

    # Standard library fallback validation
    try:
        parts = token.strip().split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = hmac.new(JWT_SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
        actual_sig = _base64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(_base64url_decode(payload_b64).decode('utf-8'))
        exp = payload.get("exp")
        if exp and int(time.time()) > int(exp):
            return None  # Token expired
        return payload
    except Exception:
        return None


# ============================================================
# BRUTE FORCE RATE LIMITING
# ============================================================

def check_login_rate_limit(client_ip: str, username: str):
    """
    Enforces rate-limits on login attempts to protect against brute-force attacks.
    """
    now = time.time()
    key = f"{client_ip}:{username.lower()}"
    recent = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < LOCKOUT_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[key] = recent

    if len(recent) >= MAX_LOGIN_ATTEMPTS:
        remaining = int(LOCKOUT_WINDOW_SECONDS - (now - recent[0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Locked out for security. Try again in {max(1, remaining // 60)} minute(s)."
        )


def record_failed_login(client_ip: str, username: str):
    """Records a failed login timestamp."""
    key = f"{client_ip}:{username.lower()}"
    now = time.time()
    if key not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[key] = []
    LOGIN_ATTEMPTS[key].append(now)


def clear_login_attempts(client_ip: str, username: str):
    """Clears failed attempts after a successful login."""
    key = f"{client_ip}:{username.lower()}"
    LOGIN_ATTEMPTS.pop(key, None)


# ============================================================
# AUTHENTICATION DEPENDENCY
# ============================================================

def get_current_user_from_request(request: Request, db: Session) -> User:
    """
    Extracts, validates, and resolves the authenticated User from:
    1. HTTP Bearer Authorization Header
    2. Raw Authorization Header
    3. URL Query Parameter 'token' (essential for browser-initiated PDF/JSON report exports)
    """
    token: Optional[str] = None

    # Check Authorization header
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
        elif len(parts) == 1:
            token = parts[0].strip()

    # Query parameter fallback (for window.open or <a> downloads)
    if not token:
        token = request.query_params.get("token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or token is invalid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials malformed.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = None
    try:
        user_id = int(sub)
        user = db.query(User).filter(User.id == user_id).first()
    except (ValueError, TypeError):
        pass

    if not user and "username" in payload:
        user = db.query(User).filter(
            func.lower(User.username) == payload["username"].lower()
        ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(lambda: SessionLocal())
) -> User:
    """FastAPI dependency for protected routes."""
    try:
        return get_current_user_from_request(request, db)
    finally:
        db.close()


# ============================================================
# STRICT DATA OWNERSHIP ENFORCEMENT HELPERS
# ============================================================

def get_user_case(case_id: str, db: Session, current_user: User) -> Case:
    """
    Retrieves a case strictly owned by current_user.
    Returns HTTP 404 (not 403) to prevent unauthorized enumeration of case IDs.
    """
    case = db.query(Case).filter(
        Case.case_id == case_id,
        Case.user_id == current_user.id
    ).first()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found or access denied."
        )

    return case


def get_user_evidence(evidence_id: str, db: Session, current_user: User) -> Tuple[Evidence, Case]:
    """
    Retrieves an evidence item strictly verifying its parent case belongs to current_user.
    Returns HTTP 404 to prevent unauthorized enumeration of evidence items.
    """
    evidence = db.query(Evidence).filter(
        Evidence.evidence_id == evidence_id
    ).first()

    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic evidence item not found."
        )

    case = db.query(Case).filter(
        Case.case_id == evidence.case_id,
        Case.user_id == current_user.id
    ).first()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic evidence item not found or access denied."
        )

    return evidence, case
