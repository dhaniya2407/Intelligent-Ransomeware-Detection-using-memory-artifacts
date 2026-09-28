# ForensiRansom AI

**AI-Based Intelligent Ransomware Detection and Automated Digital Forensic Investigation**

ForensiRansom AI is an end-to-end digital forensics and incident response (DFIR) platform designed to detect, analyze, and investigate ransomware attacks using memory artifacts, machine learning, and rule-based correlation.

---

## Key Features

- **Automated Memory Forensics**: Integrates with Volatility 3 to extract and parse memory artifacts (`pslist`, `psscan`, `pstree`, `netscan`, `cmdline`).
- **Signature & Rule-Based Detection**: Integrates YARA pattern matching to identify known ransomware families and suspicious binary signatures.
- **Machine Learning Analysis**: Trained ML model classifying memory behavioral patterns and predicting threat likelihood.
- **Dynamic Risk Scoring**: Multi-factor scoring engine evaluating process anomaly, network IOCs, file operations, and volatility artifacts.
- **Timeline & Event Correlation**: Reconstructs attack execution chronologies to identify root cause and initial access vectors.
- **Evidence & Chain of Custody**: Cryptographic SHA-256 hashing and integrity verification for all forensic artifacts.
- **Modern Web Dashboard**: Real-time interactive UI built with React, Vite, and Lucide icons for case analysts and incident responders.

---

## System Architecture

- **Backend**: Python 3.12, FastAPI, SQLAlchemy, SQLite, Volatility 3, Scikit-Learn, YARA.
- **Frontend**: React 19, Vite, Axios, React Router, Lucide Icons.

---

## Quick Start

### 1. One-Click Launch (Windows)
Double-click `start.bat` in the project root to automatically launch both backend and frontend servers.

### 2. Manual Startup

#### Backend
```bash
cd backend
# Activate virtual environment
..\.venv\Scripts\activate
# Start FastAPI application
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
- API Documentation (Swagger): [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- API Info: [http://127.0.0.1:8000/info](http://127.0.0.1:8000/info)

#### Frontend
```bash
cd frontend
npm install
npm run dev
```
- Frontend Application: [http://localhost:5173](http://localhost:5173)

---

## Project Structure

```
ForensiRansomAI/
├── backend/               # FastAPI backend & forensic APIs
│   ├── ai/                # ML feature extraction and training
│   ├── correlation/       # Event correlation engine
│   ├── detection/         # YARA and IOC detection
│   ├── forensic/          # Memory acquisition and Volatility wrappers
│   ├── reports/           # Automated forensic report generation
│   ├── main.py            # Primary FastAPI entrypoint
│   ├── database.py        # Database engine and sessions
│   └── models.py          # SQLAlchemy models
├── forensic_engine/       # Core forensic processing pipelines
├── ml_engine/             # Trained models, dataset, and predictor
├── frontend/              # React + Vite web dashboard
├── yara_rules/            # Custom and community YARA signatures
├── database/              # DB migration and schema scripts
├── analysis_results/      # Artifact parser outputs
├── start.bat              # One-click startup script
└── README.md
```

---

## License & Disclaimer
This project is developed for digital forensic research, security auditing, and defensive incident response purposes.
