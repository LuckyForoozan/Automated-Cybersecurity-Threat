# Automated Cybersecurity Threat & Incident Log Auditor

## Overview
This project provides an automated, AI-driven cybersecurity auditing pipeline that intercepts multi-source server logs and real-time user prompts.  
It applies rigorous prompt engineering principles—including analyst role definition, domain context grounding, XML formatting, and hard negative constraints—to evaluate threats accurately.  
It then outputs machine-readable, Pydantic-validated JSON triage reports that map attacker behaviors to the MITRE ATT&CK framework while guaranteeing 100% secret redaction and safe containment actions.

---

## Architecture Diagram
<img width="1800" height="1000" alt="image" src="https://github.com/user-attachments/assets/59bcb196-427d-488d-bdbc-04f3a46abe97" />



---

## Technologies Used
![Python](https://img.shields.io/badge/python-3.10+-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/dashboard-Streamlit-FF4B4B?logo=streamlit&logoColor=white)
![FastAPI](https://img.shields.io/badge/gateway-FastAPI-009688?logo=fastapi&logoColor=white)
![Uvicorn](https://img.shields.io/badge/server-Uvicorn-499848)
![Groq](https://img.shields.io/badge/served_with-Groq-F55036)
![Model](https://img.shields.io/badge/model-gpt--oss--120b-412991?logo=openai&logoColor=white)
![Pydantic](https://img.shields.io/badge/validation-Pydantic-E92063?logo=pydantic&logoColor=white)
![dotenv](https://img.shields.io/badge/config-python--dotenv-ECD53F?logo=dotenv&logoColor=black)
![Pillow](https://img.shields.io/badge/imaging-Pillow-2B5B84)
[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-app-name.streamlit.app)

link to use streamlit :https://automated-cybersecurity-threat-main.streamlit.app/

---

## Project Structure
* `step1_system_prompt.py`: Global security baselines, operational boundaries, and MITRE ATT&CK taxonomy alignment.
* `step2_role_and_behavior.py`: Lead SecOps Incident Analyst persona, calm demeanor, and false-positive suppression.
* `step3_context.py`: Domain grounding with enterprise network topology, server criticality tiers, and threat intelligence.
* `step4_constraints.py`: Hard negative constraints (zero secret leakage, non-destructive containment, anti-speculation).
* `step5_input_format.py`: Multi-source log demarcation using structured XML tags.
* `step6_structured_output.py`: Machine-readable JSON contract enforced by Pydantic schema validation.
* `step7_test_suite.py`: Automated evaluation benchmark testing benign traffic, prompt injection attacks, and critical breaches.
* `api_gateway.py`: Real-time inline HTTP firewall intercepting requests and returning `403 Forbidden` for malicious prompts.
* `app_pipeline_viewer.py`: Interactive Streamlit dashboard to toggle prompt blocks and inspect model behavior live.
