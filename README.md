# 🔍 SOC Analyst Case Study – MITRE ATT&CK Detection

## 🎯 Objective
Demonstrate how a SOC Analyst can detect and respond to real-world threats using MITRE ATT&CK and Microsoft Sentinel.

## 🛠️ Tools Used
- Microsoft Sentinel
- MITRE ATT&CK Framework
- Sysmon
- Azure Log Analytics

## 📌 Scenario
Simulated a brute-force attack targeting RDP and mapped it to ATT&CK technique `T1110.001`.

## 🔎 Detection Logic
Created KQL detection rule:
```kql
SecurityEvent
| where EventID == 4625 and AccountType == "User"
| summarize FailedAttempts = count() by Account, bin(TimeGenerated, 1h)
| where FailedAttempts > 10

✅ Outcome
Alert generated
Investigation triggered
Incident escalated

## 📸 Sentinel Alert Visualization

This screenshot shows a brute-force login detection alert generated using custom KQL in Microsoft Sentinel.

![SOC Case Study Screenshot](./soc-case-study-screenshot.png)

This detection identifies brute-force RDP attacks targeting Windows systems using Event ID 4625. It maps to MITRE ATT&CK technique T1110.001 and is implemented in Microsoft Sentinel using KQL and custom rule logic.

**MITRE Tactic:** Credential Access  
**Technique ID:** [T1110.001 – Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

Summary 
- Alert triggers on high failed login attempts
- SOC analyst validates source IP and user
- Escalation to blue team or AD team
- Block IP / Disable user




