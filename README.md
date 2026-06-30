    # Enterprise SOC Portfolio

> Ten hands-on projects building toward a full enterprise SOC simulation - Microsoft Sentinel, Defender XDR, KQL threat hunting, SOAR automation, Microsoft Purview, Security Copilot and identity threat detection with Microsoft Entra ID. Built as practical, evidence-backed preparation for the Microsoft SC-200 (Security Operations Analyst Associate) and SC-300 (Identity and Access Administrator Associate) certifications.

[![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4)](#)
[![XDR](https://img.shields.io/badge/XDR-Microsoft%20Defender-0078D4)](#)
[![Identity](https://img.shields.io/badge/Identity-Microsoft%20Entra%20ID-0078D4)](#)
[![Language](https://img.shields.io/badge/Query%20Language-KQL-blue)](#)
[![Cert](https://img.shields.io/badge/Aligned%20to-SC--200%20%7C%20SC--300-yellow)](#)

**Author:** Mojalefa "Jeff" Letsoara - SOC Analyst, SC-200 & SC-300 Candidate

---

## Why this portfolio exists

Each project here is a real, hands-on build - infrastructure stood up, attacks simulated, detections engineered, incidents triaged and lessons documented, not a tutorial follow-along. The goal is to demonstrate practical SOC Level 1 capability across the breadth of a modern Microsoft security stack, with every claim backed by a reproducible build and a written record of what broke and how it was fixed.

All lab environments are built in isolated Azure subscriptions and **decommissioned after each project's incident queue is fully resolved** to avoid ongoing cloud spend. Each project's README and report stand as the permanent evidence record.

## Roadmap

| # | Project | Focus | Status |
|---|---|---|---|
| 01 | [Microsoft Sentinel SOC Deployment](./01-microsoft-sentinel-soc-deployment/) | SIEM build, Data Collection Rules, Azure Monitor Agent, custom KQL analytics rule, MITRE ATT&CK-mapped brute-force detection, full incident lifecycle | ✅ Complete |
| 02 | Defender XDR Incident Investigation | Cross-domain correlation across endpoint, identity, and cloud apps; unified incident investigation in Microsoft Defender | 🔄 Planned |
| 03 | Advanced Threat Hunting with KQL | Proactive hunting hypotheses, hunting queries, bookmarks and custom detections built from hunt findings | 🔄 Planned |
| 04 | SOC Automation with Logic Apps | SOAR playbooks - automated triage, enrichment and response actions triggered from Sentinel incidents | 🔄 Planned |
| 05 | Microsoft Purview Insider Investigation | Insider risk management, data loss prevention and compliance-driven investigation workflow | 🔄 Planned |
| 06 | Security Copilot Assisted Investigations | AI-assisted incident investigation and response acceleration using Microsoft Security Copilot | 🔄 Planned |

### Identity & Access track (SC-300)

A SOC analyst increasingly lives in identity telemetry and most modern intrusions involve a compromised or misused identity at some stage and Defender/Sentinel's UEBA and Entra ID Protection signals are core SOC tooling, not a separate discipline. These projects are framed around *investigating and detecting* identity-based threats rather than pure identity administration so they stay directly relevant to a SOC internship rather than reading as a sysadmin detour.

| # | Project | Focus | Status |
|---|---|---|---|
| 07 | Entra ID Conditional Access & Risky Sign-In Investigation | Conditional Access policy design (MFA enforcement, location/risk-based blocking); simulating and investigating risky sign-ins (impossible travel, anonymous IP, leaked credentials) via Entra ID Protection; correlating with the Entra ID Sign-in workbook in Sentinel. Mapped to MITRE ATT&CK T1078 - Valid Accounts | 🔄 Planned |
| 08 | Privileged Identity Management (PIM) - Privilege Escalation Investigation | Configuring PIM for just-in-time eligible role assignments; simulating a privilege-escalation scenario; investigating activation audit logs; correlating against EventID 4672 privilege-use telemetry from Project 01 | 🔄 Planned |
| 09 | Identity Governance - Access Reviews & Least-Privilege Audit | Access reviews and entitlement management; documenting a compliance-driven audit of stale/excessive permissions; feeding findings into the insider-risk angle from Project 05 | 🔄 Planned |

### Capstone

| # | Project | Focus | Status |
|---|---|---|---|
| Capstone | Enterprise SOC Simulation | All nine projects integrated into one simulated enterprise environment - multi-stage attack spanning endpoint, identity and cloud; full detection-to-response chain across Sentinel, Defender XDR and Entra ID | 🔄 Planned |

## Skills demonstrated across the portfolio

- Microsoft Sentinel administration: workspaces, Data Collection Rules, Content Hub solutions, workbooks
- Kusto Query Language (KQL): ingestion validation, threat hunting, time-binned detection logic
- Microsoft Defender XDR: cross-domain incident investigation and correlation
- SOAR / automation: Logic Apps-based playbooks for triage and response
- Microsoft Purview: insider risk and compliance investigation
- Microsoft Security Copilot: AI-assisted SOC workflows
- MITRE ATT&CK framework mapping
- SOC Level 1/2 incident response lifecycle: assignment, investigation, classification, documentation, resolution
- Azure RBAC, governance tagging and infrastructure troubleshooting via CLI/PowerShell
- Microsoft Entra ID: Conditional Access policy design, Identity Protection, risk-based sign-in investigation
- Privileged Identity Management (PIM): just-in-time access, privilege escalation investigation
- Identity Governance: access reviews, entitlement management, least-privilege auditing

## Certification roadmap

| Certification | Status |
|---|---|
| SC-900 - Security, Compliance, Identity Fundamentals | ✅ Completed |
| AZ-900 - Azure Fundamentals | ✅ Completed |
| CompTIA CySA+ | ✅ Completed |
| **SC-200 - Security Operations Analyst** | 🔄 Candidate, actively preparing |
| **SC-300 - Identity and Access Administrator** | 🔄 Candidate, scheduled end of July 2026 |

---

**Connect:** open to SOC analyst / cybersecurity analyst internship and entry-level opportunities. Feel free to reach out via LinkedIn.

    
