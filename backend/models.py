from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime

from database import Base


# =========================
# CASE MODEL
# =========================

class Case(Base):
    __tablename__ = "cases"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )

    case_name = Column(
        String(200),
        nullable=False
    )

    investigator = Column(
        String(100),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    status = Column(
        String(30),
        default="Open"
    )


# =========================
# USER MODEL
# =========================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True
    )

    email = Column(
        String(150),
        unique=True,
        nullable=False
    )

    password_hash = Column(
        String(255),
        nullable=False
    )

    role = Column(
        String(50),
        default="Investigator"
    )


# =========================
# EVIDENCE MODEL
# =========================

class Evidence(Base):
    __tablename__ = "evidence"

    evidence_id = Column(
        String(100),
        primary_key=True,
        index=True
    )

    case_id = Column(
        String(50),
        nullable=False,
        index=True
    )

    filename = Column(
        String(255),
        nullable=False
    )

    file_path = Column(
        String(500),
        nullable=False
    )

    file_size = Column(
        String(50),
        nullable=False
    )

    sha256 = Column(
        String(64),
        nullable=False
    )

    evidence_type = Column(
        String(100),
        default="Memory Image"
    )

    status = Column(
        String(50),
        default="Verified"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =========================
# ANALYSIS RESULT MODEL
# =========================

class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    evidence_id = Column(
        String(100),
        nullable=False,
        index=True
    )

    analysis_type = Column(
        String(100),
        nullable=False
    )

    result = Column(
        Text,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )