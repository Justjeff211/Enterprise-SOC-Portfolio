# Project 01 — Stonegate SOC: Microsoft Sentinel Incident Response Simulation

> End-to-end SOC build, detection engineering and incident response on Microsoft Azure, from raw infrastructure to a fully triaged incident queue.

**Author:** Mojalefa "Jeff" Letsoara - SOC Analyst, SC-200 Candidate
**Build period:** 26 - 28 June 2026 · South Africa North region
**Status:** Environment decommissioned post-build to avoid ongoing Azure spend. All resources (VM, workspace, Sentinel instance, storage account) were torn down once the incident queue was fully resolved; the screenshots and queries in this repo and the full report are the evidence record.

---

## TL;DR

I built a cloud-native SOC lab from scratch on Azure - Log Analytics, Sentinel, a Windows Server 2022 endpoint, Azure Monitor Agent and a custom Data Collection Rule (DCR) then simulated a brute-force RDP attack against it and ran the full SOC Level 1 lifecycle on the result.

Along the way I found and fixed a **DCR stream misconfiguration that was invisible in the Azure Portal** and only diagnosable via PowerShell/JSON, then engineered a custom KQL-based Scheduled Analytics Rule mapped to **MITRE ATT&CK T1110 (Brute Force)**. The rule fired reliably and generated **18 incidents**, each triaged and closed through Microsoft Defender's incident management workflow — individually first to demonstrate the process, then in bulk.

| Result | Detail |
|---|---|
| Infrastructure | Resource group, Log Analytics workspace, Sentinel, storage account, Windows Server 2022 VM - fully tagged for governance |
| Critical bug found & fixed | DCR routing Windows Event Logs to `Microsoft-Event` instead of `Microsoft-SecurityEvent` - fixed via `Update-AzDataCollectionRule` |
| Detection engineered | Custom Scheduled Analytics Rule - 4+ failed logons / account / IP within 5 minutes |
| MITRE ATT&CK mapping | T1110 - Brute Force (Credential Access) |
| Incidents generated & closed | 18 / 18, individually + bulk triage, full audit trail |
| Workbooks deployed | 6, via the official Windows Security Events Content Hub solution |

---

## Why this project exists

This wasn't a tutorial follow-along. It was built as hands-on preparation for the **Microsoft SC-200 (Security Operations Analyst Associate)** certification and as evidence of practical SOC competency for internship applications. The goal was to build something, break it, diagnose the break without external help, and fix it the way a real analyst would.

## Architecture

| Component | Resource | Purpose |
|---|---|---|
| Resource Group | `rg-stonegate-soc-prod` | Logical container for all SOC resources |
| Region | South Africa North | Low latency, regional data residency |
| Log Analytics Workspace | `law-stonegate-soc` | Central telemetry repository |
| SIEM | Microsoft Sentinel (on `law-stonegate-soc`) | Detection, analytics, incident management |
| Storage Account | `ststonegatesoc01` | Log archival / diagnostic retention |
| Virtual Machine | `soc-lab-vm01` (Windows Server 2022, D2s v3) | Simulated endpoint generating telemetry |
| Monitoring Agent | Azure Monitor Agent v1.43.0.0 | Collects Windows Event Logs |
| Data Collection Rule | `dcr-soc-lab` | Defines what's collected and where it's routed |

```
RDP brute-force attempts
        │
        ▼
Windows Server 2022 (soc-lab-vm01)
        │  Local Security Policy: audit logon events (Success/Failure)
        ▼
Azure Monitor Agent
        │  via Data Collection Rule (dcr-soc-lab)
        ▼
Log Analytics Workspace (law-stonegate-soc) → SecurityEvent table
        │
        ▼
Microsoft Sentinel — Scheduled Analytics Rule (KQL, 5-min bins)
        │  MITRE ATT&CK T1110 — Brute Force
        ▼
Incident Queue (Microsoft Defender portal)
        │  Assign → Investigate → Classify → Comment → Resolve
        ▼
18/18 Incidents Resolved
```

---

## The interesting part: a misconfiguration the Portal couldn't show me

Every visible signal in the Azure Portal said the pipeline was healthy - VM agent status `Ready`, `Heartbeat` flowing, DCR showing `Provisioning succeeded` and the Security log on the VM itself sitting at 5,018 events. And yet every `SecurityEvent` query - across 24 hours, 7 days, even 30 days returned **zero results**.

The fault was in the DCR's underlying JSON, not anything the Portal UI exposed:

```powershell
Get-AzDataCollectionRule -ResourceGroupName "rg-stonegate-soc-prod" `
  -RuleName "dcr-soc-lab" |
  Select-Object -ExpandProperty DataSourceWindowsEventLog |
  Format-List *

# Stream : {Microsoft-Event}     ← WRONG. Should be Microsoft-SecurityEvent
```

The DCR's XPath filters were correct - it was correctly grabbing Application, System, and Security events - but the `Stream` property determining *which Log Analytics table that data landed in* was bound to the generic `Microsoft-Event` stream instead of `Microsoft-SecurityEvent`, the table Sentinel's detection engine and every Content Hub workbook actually reads from. Data was being ingested; it was just functionally invisible to every security tool sitting on top of it.

The fix required correcting **two separate properties** that needed to agree:

```powershell
# Fix 1 — DataFlow stream
$dcr = Get-AzDataCollectionRule -ResourceGroupName "rg-stonegate-soc-prod" -RuleName "dcr-soc-lab"
$dcr.DataFlow[0].Stream = @("Microsoft-SecurityEvent")
Update-AzDataCollectionRule -ResourceGroupName "rg-stonegate-soc-prod" -RuleName "dcr-soc-lab" `
  -DataFlow $dcr.DataFlow -DataSourceWindowsEventLog $dcr.DataSourceWindowsEventLog `
  -DestinationLogAnalytic $dcr.DestinationLogAnalytic

# Fix 2 — DataSourceWindowsEventLog stream (the partial fix above wasn't enough)
$dcr = Get-AzDataCollectionRule -ResourceGroupName "rg-stonegate-soc-prod" -RuleName "dcr-soc-lab"
$dcr.DataSourceWindowsEventLog[0].Stream = @("Microsoft-SecurityEvent")
Update-AzDataCollectionRule -ResourceGroupName "rg-stonegate-soc-prod" -RuleName "dcr-soc-lab" `
  -DataFlow $dcr.DataFlow -DataSourceWindowsEventLog $dcr.DataSourceWindowsEventLog `
  -DestinationLogAnalytic $dcr.DestinationLogAnalytic
```

Within minutes of the second fix, `SecurityEvent` returned 38 distinct EventIDs - including the EventID 4625 failed-logon pattern this project was built to detect.

**Takeaway:** `Provisioning succeeded` confirms a resource was created. It says nothing about whether its internal routing logic is correct. The only reliable verification is querying the destination table directly.

---

## Detection logic

Prototyped directly in Sentinel Logs against real attack telemetry before ever being wired into a formal rule:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 3
| order by FailedAttempts desc
```

This became the **Scheduled Analytics Rule** query, mapped to:

- **Tactic:** Credential Access
- **Technique:** T1110 - Brute Force
- **Entities mapped:** `Account` (Name), `IpAddress` (Address)

### A second bug: the lookback window race condition

The first scheduling attempt set both **Run query every** and **Lookup data from the last** to 5 minutes. which sounds reasonable since the detection logic itself bins data into 5-minute windows. In practice, if the rule's execution cycle landed even slightly out of phase with the attack telemetry, the 5-minute lookback wouldn't reliably contain a complete bin, and the rule would silently fail to fire despite correct data and correct logic.

**Fix:** widened the lookback to 30 minutes while keeping the 5-minute execution cadence, thus giving the rule six chances to catch any 5-minute brute-force bin in the preceding half hour.

**Takeaway:** a rule's lookback window must be generously wider than its own detection bin or genuine attack telemetry can fall just outside the scan window purely due to execution timing.

---

## Incident response workflow

The rule generated **18 incidents**. Each was run through a structured SOC Level 1 lifecycle:

1. **Assign** - analyst ownership set
2. **Status → In Progress** - investigation begins
3. **Investigate** - incident graph / attack story view connects the `Account` entity to the `IP` entity
4. **Classify** - `Informational, expected activity` → `Security testing`
5. **Document** - analyst comment logged with EventIDs, IPs, and reasoning (full audit trail, timestamped)
6. **Resolve** - explicit closure justification required by Defender before resolution

The first incident was closed individually to demonstrate the full workflow; the remaining 17 were closed via **bulk incident management** — same classification, same assignment, same resolution, applied across the whole queue in one action.

---

## SC-200 exam domain coverage

| SC-200 Domain | Demonstrated by |
|---|---|
| Mitigate threats using Microsoft Sentinel | Built `law-stonegate-soc` from scratch; onboarded Sentinel; Content Hub solution install |
| Configure protections / detections | Custom Scheduled Analytics Rule, KQL logic, MITRE mapping, entity mapping |
| Manage incident response | Full lifecycle across 18 incidents - individual and bulk |
| Kusto Query Language (KQL) | Ingestion checks, Heartbeat validation, EventID filtering, time-binned aggregation |
| Data Collection Rules & AMA | Diagnosed and fixed a real DCR stream misconfiguration via PowerShell |
| MITRE ATT&CK framework | Mapped detection to Credential Access / T1110 |
| Workbooks & Content Hub | Windows Security Events solution; 6 workbooks deployed |
| Azure RBAC | Diagnosed and resolved a workspace permissions gap (Log Analytics Contributor) |

---

## Lessons learned

- A green provisioning status doesn't guarantee a working pipeline - only querying the destination table does.
- The Azure Portal can hide configuration that PowerShell/JSON exposes directly.
- A detection rule's lookback window must be wider than its own detection bin size.
- Windows Security event logging requires explicit Local Security Policy configuration - out of the box, Windows Server logs almost nothing security-relevant.
- Default VM deployment behavior auto-generates a new resource group unless one is explicitly selected - easy to overlook and the direct cause of the first AMA install failure.

## Recommendations for a production deployment

- Define DCRs as Infrastructure as Code (Bicep/Terraform) so stream-binding mismatches are visible at review time, not in production.
- Build a standing "pipeline health" workbook that alerts if `Heartbeat`, `SecurityEvent`, or `AzureActivity` ingestion goes quiet.
- Extend the rule library to privilege escalation (4672), account lockouts (4740), and object access anomalies (4663) — all observed in this environment but not yet alerted on.
- Add a SOAR playbook to automate routine triage (assignment, initial classification, notification).
- Review RBAC on a recurring schedule rather than reactively.

---

## Full report

This README is the technical summary. The complete walkthrough - every phase, every screenshot, every troubleshooting step in full detail — is in the full portfolio report:

📄 [`/docs/Stonegate_SOC_Sentinel_IR_Portfolio.pdf`](./docs/Stonegate_SOC_Sentinel_IR_Portfolio.pdf)

## Appendix - KQL reference library

```kql
// Baseline workspace check
search *
| where TimeGenerated > ago(1h)
| summarize Count=count() by $table

// Agent connectivity
Heartbeat
| summarize Count = count() by Computer

// Broad SecurityEvent ingestion check
SecurityEvent
| where TimeGenerated > ago(30m)
| summarize count() by EventID
| order by count_ desc

// Failed logons
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IpAddress, FailureReason
| order by TimeGenerated desc

// Successful logons
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, LogonType, IpAddress
| order by TimeGenerated desc

// Brute-force aggregation (production rule query)
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 3
| order by FailedAttempts desc

// Privilege escalation (future detection)
SecurityEvent
| where EventID == 4672
| project TimeGenerated, Computer, Account, Privileges
| order by TimeGenerated desc

// Object / file access (future detection)
SecurityEvent
| where EventID == 4663
| project TimeGenerated, Account, ObjectName, AccessMask
| order by TimeGenerated desc

// Activity log ingestion check
AzureActivity
| take 10
```

---

## Certification roadmap

| Certification | Status |
|---|---|
| SC-900 - Security, Compliance, Identity Fundamentals | ✅ Completed |
| AZ-900 - Azure Fundamentals | ✅ Completed |
| CompTIA Security+ | ✅ Completed |
| CompTIA CySA+ | ✅ Completed |
| **SC-200 - Security Operations Analyst** | 🔄 Candidate, actively preparing |
| SC-300 - Identity and Access Administrator | 📅 Scheduled, end of July 2026 |

---

**Connect:** Feel free to reach out via LinkedIn.
https://www.linkedin.com/in/mojalefa-l-letsoara283b5a211/
    
