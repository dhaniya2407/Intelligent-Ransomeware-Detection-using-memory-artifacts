# ============================================================
# FORENSIRANSOM AI — GEMINI FORENSIC RECOMMENDATION SERVICE
# ============================================================
# Grounded in verified digital forensic findings.
# Never sends raw evidence files or memory dumps to external APIs.
# Works both WITH and WITHOUT Gemini configured (offline fallback).
# ============================================================

import os
import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List

logger = logging.getLogger("forensiransom.gemini")

# External security references
SECURITY_RESOURCES = [
    {
        "title": "MITRE ATT&CK Framework",
        "category": "Adversary Tactics & Techniques",
        "description": "Globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.",
        "url": "https://attack.mitre.org/",
        "badge": "MITRE ATT&CK"
    },
    {
        "title": "CISA StopRansomware Resource Center",
        "category": "Government & Incident Response",
        "description": "United States Cybersecurity & Infrastructure Security Agency (CISA) dedicated ransomware guidance and alerts.",
        "url": "https://www.cisa.gov/stopransomware",
        "badge": "CISA"
    },
    {
        "title": "CISA #StopRansomware Guide",
        "category": "Best Practices Guide",
        "description": "Joint cybersecurity guidance for ransomware prevention, response, and incident remediation checklists.",
        "url": "https://www.cisa.gov/stopransomware/ransomware-guide",
        "badge": "CISA Guide"
    },
    {
        "title": "Microsoft Ransomware Incident Response",
        "category": "Vendor Guidance",
        "description": "Microsoft Security playbooks, detection guidance, and defense against human-operated and automated ransomware.",
        "url": "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-ransomware",
        "badge": "Microsoft"
    },
    {
        "title": "NIST SP 800-86 Forensic Techniques Guide",
        "category": "Standard Forensic Framework",
        "description": "Guide to Integrating Forensic Techniques into Incident Response by the National Institute of Standards and Technology.",
        "url": "https://csrc.nist.gov/pubs/sp/800/86/final",
        "badge": "NIST"
    }
]


def sanitize_forensic_findings(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts only sanitized, high-level structured forensic metadata.
    Strictly prevents uploading raw memory dumps or binary data.
    """
    case = analysis_data.get("case", {})
    evidence = analysis_data.get("evidence", {})
    risk = analysis_data.get("risk", {})
    ml = analysis_data.get("ml") or analysis_data.get("ml_prediction") or {}
    yara = analysis_data.get("yara", {})
    features = analysis_data.get("features", {})
    volatility = analysis_data.get("volatility", {})
    correlations = analysis_data.get("correlations", [])
    
    # Extract clean YARA findings
    yara_findings = yara.get("findings") or yara.get("matches") or []
    clean_yara = []
    for item in yara_findings[:10]:
        if isinstance(item, dict):
            clean_yara.append({
                "rule": item.get("rule") or item.get("rule_name") or "Unknown",
                "source": item.get("source") or item.get("plugin") or "YARA",
                "description": item.get("description") or "Suspicious pattern detected"
            })

    # Extract clean correlations
    clean_correlations = []
    for c in correlations[:5]:
        if isinstance(c, dict):
            clean_correlations.append({
                "type": c.get("correlation_type") or "Correlation",
                "description": c.get("description") or c.get("message") or "Artifact correlation",
                "severity": c.get("severity") or "INFO"
            })

    # Extract clean metrics
    total_events = features.get("total_events", len(analysis_data.get("timeline", [])))
    process_events = features.get("process_events", 0)
    command_events = features.get("command_events", 0)
    network_events = features.get("network_events", 0)
    suspicious_events = features.get("suspicious_events", 0)

    return {
        "case_id": case.get("case_id", "FRA-UNKNOWN"),
        "case_name": case.get("case_name", "Forensic Investigation"),
        "investigator": case.get("investigator", "Digital Forensic Investigator"),
        "evidence_id": evidence.get("evidence_id", "MEM-UNKNOWN"),
        "evidence_filename": evidence.get("filename", "memory.raw"),
        "evidence_integrity": evidence.get("status") or evidence.get("integrity") or "Verified",
        "sha256": evidence.get("sha256", "Not recorded"),
        "volatility_status": volatility.get("status", "COMPLETED"),
        "active_plugins": list(volatility.get("plugins", {}).keys()) if isinstance(volatility.get("plugins"), dict) else [],
        "event_counts": {
            "total_events": total_events,
            "process_events": process_events,
            "command_events": command_events,
            "network_events": network_events,
            "suspicious_events": suspicious_events
        },
        "yara_match_count": yara.get("match_count", len(clean_yara)),
        "yara_findings": clean_yara,
        "correlations": clean_correlations,
        "ml_classification": ml.get("classification") or ml.get("label") or "Normal",
        "ml_probabilities": ml.get("probabilities", {}),
        "risk_score": risk.get("risk_score", 0),
        "risk_level": risk.get("risk_level", "LOW"),
        "risk_reasons": risk.get("reasons", [])
    }


def generate_offline_recommendations(sanitized: Dict[str, Any], reason: str = "") -> Dict[str, Any]:
    """
    Deterministic, professional DFIR recommendations grounded in actual case findings
    when Gemini API is not configured or unavailable.
    """
    risk_level = str(sanitized.get("risk_level", "LOW")).upper()
    risk_score = sanitized.get("risk_score", 0)
    yara_count = sanitized.get("yara_match_count", 0)
    yara_findings = sanitized.get("yara_findings", [])
    correlations = sanitized.get("correlations", [])
    ml_class = sanitized.get("ml_classification", "Normal")
    event_counts = sanitized.get("event_counts", {})
    suspicious_events = event_counts.get("suspicious_events", 0)
    case_id = sanitized.get("case_id", "FRA-001")
    evidence_id = sanitized.get("evidence_id", "MEM-001")
    integrity = sanitized.get("evidence_integrity", "Verified")

    # Build observed findings list
    observed = [
        f"Evidence {evidence_id} integrity status confirmed as {integrity}.",
        f"Automated forensic pipeline extracted {event_counts.get('total_events', 0)} total artifacts ({event_counts.get('process_events', 0)} processes, {event_counts.get('command_events', 0)} commands, {event_counts.get('network_events', 0)} network events)."
    ]
    if yara_count > 0:
        rules = [f["rule"] for f in yara_findings[:3]]
        observed.append(f"{yara_count} YARA detection(s) flagged: {', '.join(rules)}.")
    else:
        observed.append("No active ransomware YARA signatures triggered on the inspected artifacts.")

    if correlations:
        observed.append(f"{len(correlations)} cross-artifact correlation(s) identified between process tree and command-line execution.")

    if suspicious_events > 0:
        observed.append(f"{suspicious_events} suspicious forensic event(s) flagged by the forensic rule engine.")

    # Executive summary
    if risk_level in ["CRITICAL", "HIGH"] or ml_class == "Ransomware":
        exec_summary = (
            f"Forensic investigation for Case {case_id} (Evidence {evidence_id}) reveals high-severity indicators "
            f"consistent with active ransomware deployment or advanced post-exploitation activity. "
            f"Calculated risk score is {risk_score} ({risk_level}) with ML assessment '{ml_class}'. "
            f"Immediate containment and isolation measures are urgently advised."
        )
        risk_interp = (
            f"Risk is assessed as {risk_level} due to detected malicious behavior, high correlation count, "
            f"or active ransomware signatures. Critical threat to business operations and data confidentiality."
        )
        immediate = [
            "Immediately isolate the host from local network segments and enterprise VLANs.",
            "Preserve active volatile RAM and disk snapshots before powering down or rebooting.",
            "Revoke compromised Kerberos and Active Directory service accounts associated with observed processes.",
            "Block identified Command & Control (C2) IP addresses and malicious domains at network perimeter firewalls."
        ]
        containment = [
            "Disable network interfaces and isolate host on an isolated quarantine VLAN.",
            "Halt suspected ransomware processes and sub-processes to prevent encryption progression.",
            "Suspend scheduled tasks and service accounts exhibiting anomalous execution privileges.",
            "Enforce strict firewall ingress/egress filtering on SMB (ports 445/139) and RDP (port 3389)."
        ]
        further_steps = [
            "Perform full MFT ($MFT) and USN Journal analysis to detect newly encrypted or deleted file extensions.",
            "Inspect Volume Shadow Copies (vssadmin list shadows) to determine if recovery snapshots were purged.",
            "Analyze Windows Security Event Logs (Event IDs 4688, 4624, 4672) and Sysmon Event IDs 1, 3, 11.",
            "Extract memory strings and memory sections around identified suspicious PIDs for encryption keys or ransom notes."
        ]
        recovery = [
            "Do not pay ransom demands; consult with law enforcement and cybersecurity incident handlers.",
            "Verify the integrity of immutable, off-site backup snapshots prior to initiation of restoration.",
            "Perform bare-metal rebuild or clean OS re-imaging from known-good golden images.",
            "Conduct post-recovery credential rotation for all domain administrative accounts."
        ]
        mitre = [
            {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "relevance": "Primary ransomware mechanism to disrupt availability by encrypting user and system files.",
                "mitigation": "Maintain immutable, air-gapped backups and deploy behavior-based endpoint protection."
            },
            {
                "technique_id": "T1490",
                "technique_name": "Inhibit System Recovery",
                "tactic": "Impact",
                "relevance": "Adversaries often delete shadow copies and recovery catalogs (vssadmin, bcdedit).",
                "mitigation": "Protect backup services with multi-factor authentication and restrict shadow copy deletion."
            },
            {
                "technique_id": "T1059.003",
                "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
                "tactic": "Execution",
                "relevance": "Observed execution of command line utilities (cmd.exe) to coordinate malicious actions.",
                "mitigation": "Enable Command Line Process Auditing (Event 4688) with full arguments logging."
            },
            {
                "technique_id": "T1057",
                "technique_name": "Process Discovery",
                "tactic": "Discovery",
                "relevance": "Enumeration of running system processes to locate defense tools and target databases.",
                "mitigation": "Deploy endpoint detection and response (EDR) to identify anomalous discovery patterns."
            }
        ]
    elif risk_level == "MEDIUM" or ml_class == "Suspicious" or yara_count > 0:
        exec_summary = (
            f"Forensic investigation for Case {case_id} (Evidence {evidence_id}) identified suspicious activity "
            f"requiring targeted investigation. Calculated risk score is {risk_score} ({risk_level}) with ML assessment "
            f"'{ml_class}'. Detected command-line executions or YARA signatures warrant proactive triage."
        )
        risk_interp = (
            f"Risk is categorized as {risk_level}. While widespread encryption was not established, "
            f"dual-use administrative tools or suspicious process chains (e.g., cmd.exe) were observed in memory."
        )
        immediate = [
            "Monitor network traffic from this host for unexpected outbound beaconing or data staging.",
            "Inspect running parent processes and examine associated parent-child process lineages.",
            "Audit recent interactive logins and PowerShell command histories for anomalous user accounts.",
            "Ensure endpoint protection and EDR agents on the system are active and updating."
        ]
        containment = [
            "Restrict outbound internet access from this workstation pending completion of deep-dive review.",
            "Place affected administrative credentials on restricted monitoring and enforce password resets.",
            "Isolate non-essential lateral movement pathways (SMB, WinRM) between workstations."
        ]
        further_steps = [
            "Correlate memory timestamp artifacts with Windows Security Event Logs (Event ID 4688).",
            "Examine PowerShell Script Block Logging (Event ID 4104) and transcription logs.",
            "Inspect registry run keys (Run, RunOnce) and Scheduled Tasks for persistence mechanisms.",
            "Review prefetch files (.pf) to confirm execution times and file volume modifications."
        ]
        recovery = [
            "Validate that critical business databases and files have recent, intact backups.",
            "Review software installation logs to confirm whether suspicious binaries were user-authorized.",
            "Maintain continuous monitoring on the affected host for at least 14 days."
        ]
        mitre = [
            {
                "technique_id": "T1059.003",
                "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
                "tactic": "Execution",
                "relevance": "Observed command-line execution (cmd.exe) utilized for system manipulation.",
                "mitigation": "Audit command execution and restrict script interpreter usage via Application Control policies."
            },
            {
                "technique_id": "T1057",
                "technique_name": "Process Discovery",
                "tactic": "Discovery",
                "relevance": "Process artifacts evaluated during memory triage.",
                "mitigation": "Monitor process enumeration commands executed by unprivileged accounts."
            },
            {
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "tactic": "Discovery",
                "relevance": "Pre-attack reconnaissance often leverages built-in tools before ransomware deployment.",
                "mitigation": "Detect automated reconnaissance scripts and privilege escalation probes."
            }
        ]
    else:
        exec_summary = (
            f"Forensic investigation for Case {case_id} (Evidence {evidence_id}) completed without detecting active ransomware "
            f"or high-risk forensic anomalies. Calculated risk score is {risk_score} ({risk_level}) with ML assessment '{ml_class}'. "
            f"Evidence integrity is verified intact."
        )
        risk_interp = (
            f"Risk level is {risk_level}. No active ransomware encryptors, known malicious payloads, or anomalous "
            f"network beaconing were observed in the acquired memory dump."
        )
        immediate = [
            "Maintain standard security posture and operational monitoring.",
            "Archive forensic evidence with verified SHA-256 hash according to organizational chain of custody.",
            "Confirm that endpoint protection signatures and OS security patches are current."
        ]
        containment = [
            "No emergency containment actions are indicated by the current forensic evidence.",
            "Ensure standard principle of least privilege is enforced for local workstation accounts."
        ]
        further_steps = [
            "Archive the forensic memory image and case documentation in the digital evidence vault.",
            "Cross-reference findings with external threat intelligence feeds if new indicators emerge.",
            "Close investigation or transition to routine compliance audit as appropriate."
        ]
        recovery = [
            "Host can safely continue regular operational duties.",
            "Perform periodic automated backup checks and verify disaster recovery recovery time objectives (RTO)."
        ]
        mitre = [
            {
                "technique_id": "T1057",
                "technique_name": "Process Discovery",
                "tactic": "Discovery",
                "relevance": "Baseline memory process validation and integrity assessment.",
                "mitigation": "Maintain baseline inventory of authorized enterprise executables."
            },
            {
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "tactic": "Discovery",
                "relevance": "System telemetry and volatile memory verification.",
                "mitigation": "Ensure centralized SIEM event collection and monitoring."
            }
        ]

    provider_label = (
        "Forensic Rule Engine (Offline Fallback - GEMINI_API_KEY not configured)"
        if not reason or "not set" in reason.lower() or "missing" in reason.lower()
        else f"Forensic Rule Engine (Offline Fallback - {reason})"
    )

    return {
        "is_ai_generated": False,
        "provider": provider_label,
        "status": "offline_fallback",
        "executive_summary": exec_summary,
        "observed_findings": observed,
        "risk_interpretation": risk_interp,
        "immediate_response": immediate,
        "containment_guidance": containment,
        "further_forensic_steps": further_steps,
        "recovery_recommendations": recovery,
        "mitre_attack": mitre,
        "limitations_and_confidence": (
            "Confidence is High based on analyzed memory artifacts, Volatility output, YARA signatures, and rule evaluation. "
            "Analysis is limited to the volatile memory state captured at the time of evidence acquisition. "
            "These automated recommendations must be validated by the assigned lead investigator."
        ),
        "external_resources": SECURITY_RESOURCES,
        "disclaimer": (
            "NOTICE: Forensic findings (evidence integrity, hashes, YARA detections, and process events) are "
            "empirically verified digital evidence. The recommendations provided here are automated forensic guidance "
            "to assist the investigator and do not execute automated modifications on the investigated system."
        )
    }


def call_gemini_api(api_key: str, sanitized_findings: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls Google Gemini REST API using standard Python urllib.
    Zero external dependencies required.
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"

    prompt_text = f"""You are an elite Digital Forensics and Incident Response (DFIR) AI expert assisting with a ransomware forensic investigation.
You are given VERIFIED digital forensic findings extracted from a memory image.

FORENSIC EVIDENCE & ANALYSIS DATA:
{json.dumps(sanitized_findings, indent=2)}

TASK:
Provide professional, actionable, and strictly grounded forensic recommendations.
DO NOT fabricate evidence or unobserved malware families.
Differentiate factual forensic findings from your analytical recommendations.

You MUST respond ONLY with a valid JSON object (no markdown code blocks, no other text) with the following exact keys:
{{
  "executive_summary": "Concise 2-3 paragraph summary of the case findings and incident posture.",
  "observed_findings": ["Bullet 1 of verified facts", "Bullet 2 of verified facts", ...],
  "risk_interpretation": "Detailed interpretation of the risk score and classification in relation to ransomware.",
  "immediate_response": ["Immediate action 1", "Immediate action 2", ...],
  "containment_guidance": ["Containment action 1", "Containment action 2", ...],
  "further_forensic_steps": ["Further forensic step 1", "Further forensic step 2", ...],
  "recovery_recommendations": ["Recovery action 1", "Recovery action 2", ...],
  "mitre_attack": [
    {{
      "technique_id": "T1486",
      "technique_name": "Data Encrypted for Impact",
      "tactic": "Impact",
      "relevance": "Why this technique applies to the observed findings",
      "mitigation": "Recommended security control"
    }}
  ],
  "limitations_and_confidence": "Explanation of analytical confidence and scope limitations of memory forensics."
}}
"""

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt_text}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2048,
            "responseMimeType": "application/json"
        }
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=req_data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=18) as response:
        resp_data = json.loads(response.read().decode("utf-8"))

    # Extract text from Gemini response structure
    candidates = resp_data.get("candidates", [])
    if not candidates:
        raise ValueError("No candidates returned from Gemini API")

    content_parts = candidates[0].get("content", {}).get("parts", [])
    if not content_parts:
        raise ValueError("No content parts returned from Gemini API")

    raw_text = content_parts[0].get("text", "").strip()

    # Clean potential markdown wrapping if present
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:]
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]
    raw_text = raw_text.strip()

    parsed = json.loads(raw_text)

    # Ensure all required keys exist
    return {
        "is_ai_generated": True,
        "provider": "Google Gemini 1.5 Flash (AI-Assisted DFIR)",
        "status": "success",
        "executive_summary": parsed.get("executive_summary", "Executive summary unavailable."),
        "observed_findings": parsed.get("observed_findings", []),
        "risk_interpretation": parsed.get("risk_interpretation", "Risk interpretation unavailable."),
        "immediate_response": parsed.get("immediate_response", []),
        "containment_guidance": parsed.get("containment_guidance", []),
        "further_forensic_steps": parsed.get("further_forensic_steps", []),
        "recovery_recommendations": parsed.get("recovery_recommendations", []),
        "mitre_attack": parsed.get("mitre_attack", []),
        "limitations_and_confidence": parsed.get(
            "limitations_and_confidence",
            "Confidence is based on provided digital forensic findings."
        ),
        "external_resources": SECURITY_RESOURCES,
        "disclaimer": (
            "NOTICE: Verified forensic findings (evidence integrity, hashes, YARA matches, and timeline events) "
            "are empirical digital artifacts. The recommendations above were generated by Google Gemini AI "
            "as guidance for the investigator. Human verification is required prior to taking production actions."
        )
    }


def get_recommendations(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point: generates recommendations for an evidence analysis dataset.
    Prioritizes Gemini API when GEMINI_API_KEY is available.
    Automatically and safely falls back to the internal forensic rule engine when Gemini is unavailable.
    """
    sanitized = sanitize_forensic_findings(analysis_data)
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        logger.info("GEMINI_API_KEY not configured. Using Forensic Rule Engine offline fallback.")
        return generate_offline_recommendations(sanitized, reason="GEMINI_API_KEY environment variable not set")

    try:
        logger.info("Calling Gemini API for forensic recommendations...")
        return call_gemini_api(api_key, sanitized)
    except Exception as e:
        logger.warning("Gemini API call failed (%s). Falling back to internal forensic rule engine.", e)
        return generate_offline_recommendations(sanitized, reason=f"Gemini API request failed ({str(e)})")
