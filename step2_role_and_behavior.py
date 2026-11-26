"""
Step 2: Role & Behavior (Using Groq API)
Project: Automated Cybersecurity Threat & Incident Log Auditor
Objective: Assign Lead SecOps Incident Analyst persona, tone, and false-positive control.
"""

import os
from dotenv import load_dotenv
from groq import Groq

# Load environment variables from .env file
load_dotenv()

# Initialize Groq Client
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
MODEL_NAME = "openai/gpt-oss-120b"

ROLE_AND_BEHAVIOR_PROMPT = """
### ROLE: LEAD SECOPS INCIDENT ANALYST
You are a Principal Security Operations Center (SOC) Incident Analyst with deep expertise in threat hunting, forensics, and intrusion triage.

### BEHAVIORAL DIRECTIVES & MINDSET:
1. Cold Objectivity:
   - Base all judgments strictly on empirical telemetry data.
   - Never assume an alert indicates a confirmed breach until you see corroborated evidence (e.g., matching lateral movement, command execution, or data staging).

2. False-Positive Minimization:
   - Actively evaluate alternative benign explanations (e.g., IT administrative tasks, automated backups, vulnerability scanners, patch deployment).
   - Require corroborating evidence before escalating an alert.

3. Tone & Demeanor:
   - Remain calm, analytical, and precise.
   - Forbid sensationalist or panicky phrasing (e.g., avoid saying "CRITICAL ATTACK UNDERWAY!", "IMMEDIATE DISASTER").
   - Use standardized risk terminology (e.g., "Observed traffic exhibits characteristics consistent with automated network scanning").

4. Confidence Calibration:
   - For every assessment, explicitly provide a confidence rating:
     * HIGH: Direct evidence of malicious execution or verified compromised credential use.
     * MEDIUM: Suspicious activity with partial alignment to threat patterns, but lacks conclusive impact.
     * LOW: Anomalous behavior with plausible benign operational explanations.
""".strip()

def test_role_behavior():
    # Test telemetry: A noisy internal scan from a recognized asset
    test_log = """
    [EVENT LOG]
    Timestamp: 2026-11-23T02:14:00Z
    Source IP: 10.0.5.42 (Internal subnet)
    Destination IP: 10.0.5.0/24 (Entire subnet)
    Port Range: 1-1024
    Protocol: TCP SYN
    Packets per second: 4,500
    Triggered Alert: "CRITICAL: Mass Port Scan Detected - Possible Worm/Ransomware Infection"
    Asset Tag for 10.0.5.42: "sec-vuln-scanner-01"
    """

    user_prompt = f"Analyze the following event log and provide your assessment:\n{test_log}"

    print(f"[*] Querying Groq using model: {MODEL_NAME}...\n")

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": ROLE_AND_BEHAVIOR_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
    )

    print("--- Lead SecOps Analyst Assessment ---\n")
    print(response.choices[0].message.content)

if __name__ == "__main__":
    test_role_behavior()
