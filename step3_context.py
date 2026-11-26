"""
Step 3: Context Grounding (Using Groq API)
Project: Automated Cybersecurity Threat & Incident Log Auditor
Objective: Ground the model with enterprise network topology, asset criticality tiers,
           approved maintenance schedules, and active threat advisories.
"""

import os
from dotenv import load_dotenv
from groq import Groq

# Load environment variables from .env
load_dotenv()

# Initialize Groq Client
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
MODEL_NAME = "openai/gpt-oss-120b"

# ==============================================================================
# BASE SYSTEM INSTRUCTION (Step 1 + Step 2 Combined)
# ==============================================================================
SYSTEM_INSTRUCTION = """
You are an autonomous, high-assurance Cybersecurity Incident & Threat Log Auditor acting as a Lead SecOps Incident Analyst.
Maintain strict objectivity, evidence-based reasoning, false-positive control, and MITRE ATT&CK alignment.
""".strip()

# ==============================================================================
# STEP 3: CONTEXT BLOCK (Domain & Environment Knowledge Grounding)
# ==============================================================================
CONTEXT_KNOWLEDGE = """
### ENTERPRISE INFRASTRUCTURE CONTEXT:

1. Network Architecture & Subnet Segmentation:
   - 10.0.1.0/24: [ZONE: PROD-DATA] Critical production databases and customer vaults. Air-gapped from direct internet access.
   - 10.0.2.0/24: [ZONE: DMZ-WEB] Public-facing web application servers and reverse proxies.
   - 10.0.5.0/24: [ZONE: SEC-MGMT] Security management, bastion hosts, and vulnerability scanners.
   - 192.168.100.0/24: [ZONE: DEV-SANDBOX] Non-sensitive developer test environments.

2. Asset Criticality Hierarchy:
   - TIER 1 (Mission Critical): 
     * 10.0.1.10 (`prod-db-primary`): Primary financial transactions database.
     * 10.0.1.15 (`auth-vault-01`): Kerberos & Key Management server.
     * Impact: Any unauthorized access attempt is an immediate P1 incident.
   - TIER 2 (Operational): Web and API endpoints in DMZ (10.0.2.x).
   - TIER 3 (Low): Sandbox machines in 192.168.100.x.

3. Operational Baselines & Approved Schedules:
   - Vulnerability Scanning: Scheduled ONLY on Sundays between 01:00 UTC and 04:00 UTC from source `10.0.5.42`.
   - Out-of-window scans or scans against Tier-1 databases from non-security subnets are strictly unauthorized.

4. Active Threat Advisory (Threat Intel):
   - CVE-2024-3094 / Malicious SSH backdoor circulating in the wild targeting port 22 on Linux hosts.
   - Known C2 IP Range flagged by Threat Intel: `203.0.113.0/24`.
""".strip()

# ==============================================================================
# TEST RUN: Verifying Context Utilization
# ==============================================================================
def test_context_awareness():
    # Test Telemetry: Unauthorized connection attempt directly hitting a Tier-1 DB
    incident_log = """
    [FIREWALL ALERT - INGRESS VIOLATION]
    Timestamp: 2026-11-23T14:15:22Z (Monday afternoon - Non-maintenance window)
    Source IP: 203.0.113.88 (External Internet)
    Destination IP: 10.0.1.10 (Internal Port: 22 / SSH)
    Action: DROPPED by perimeter firewall (Rule: DENY-DIRECT-DB-ACCESS)
    Connection Attempts: 142 failed handshakes within 60 seconds
    """

    user_prompt = f"""
{CONTEXT_KNOWLEDGE}

============================================================
INCOMING TELEMETRY TO AUDIT:
{incident_log}
============================================================

Evaluate this incident using the enterprise context provided above. 
Identify the target asset, its criticality tier, network zone violation, and correlate with active threat intelligence.
"""

    print(f"[*] Querying Groq using model: {MODEL_NAME}...\n")

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
    )

    print("--- Context-Grounded SecOps Audit ---\n")
    print(response.choices[0].message.content)

if __name__ == "__main__":
    test_context_awareness()
