# Microsoft Sentinel – KQL Queries  

## 🎯 Objective  
Develop and test detection queries in Microsoft Sentinel to improve SOC visibility and threat-detection capabilities.  

## 🧠 Tools & Environment  
- Microsoft Sentinel (LA Workspace)  
- Azure Active Directory Sign-in Logs / SecurityEvent Tables  
- Microsoft Defender for Endpoint data  
- Kusto Query Language (KQL)  

---

## ⚙️ Detection Queries  

### 🔹 Brute Force Login Detection  
```kql
SecurityEvent
| where EventID == 4625
| summarize Failed =count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where Failed >= 10
```
**MITRE:** T1110 – Brute Force  

---

### 🔹 Suspicious PowerShell Execution  
```kql
SecurityEvent
| where EventID == 4104 or (EventSourceName == "Microsoft-Windows-PowerShell")
| where CommandLine has_any ("EncodedCommand","FromBase64String")
| project TimeGenerated, Account, Computer, CommandLine
```
**MITRE:** T1059 – Command and Scripting Interpreter  

---

### 🔹 Failed RDP Connections  
```kql
SecurityEvent
| where EventID == 4625 and LogonType == 10
| summarize count() by Account, IpAddress, bin(TimeGenerated, 10m)
| where count_ > 5
```
**MITRE:** T1021 – Remote Services  

---

## 📊 Screenshots (to add later)  
- Logs query with results  
- Analytics rule setup window  
- Triggered incident overview  

Store them in `/images/` (create this folder later).  

---

## 🏁 Next Steps  
- Add correlation rules across multiple tables.  
- Integrate Defender for Cloud alerts and custom watchlists.  
- Map each query to MITRE ATT&CK techniques.  
