from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import os


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# DATABASE PATH
# ============================================================

DATABASE_PATH = os.path.join(
    PROJECT_ROOT,
    "forensic.db"
)

if not os.path.exists(DATABASE_PATH):
    for candidate in [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensic.db"),
        os.path.join(os.getcwd(), "forensic.db"),
    ]:
        if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
            DATABASE_PATH = candidate
            break


DATABASE_URL = (
    "sqlite:///"
    + DATABASE_PATH.replace("\\", "/")
)


# ============================================================
# DATABASE ENGINE
# ============================================================

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    }
)


# ============================================================
# SESSION
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# ============================================================
# BASE MODEL
# ============================================================

Base = declarative_base()