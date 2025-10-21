# 🛡️ Microsoft Sentinel – KQL Queries  

## 🎯 Objective  
Develop and test detection queries in Microsoft Sentinel to improve SOC visibility and threat-detection capabilities.  
These detections are part of the **SOC Analyst Portfolio**, showcasing practical SIEM and KQL skills.  

---

## 🧠 Tools & Environment  
- Microsoft Sentinel (Log Analytics Workspace)  
- Azure Active Directory Sign-in Logs / SecurityEvent Tables  
- Microsoft Defender for Endpoint data  
- Kusto Query Language (KQL)  

---

## ⚙️ Detection Queries  

### 🔹 Brute Force Login Detection  
```kql
SecurityEvent
| where EventID == 4625
| summarize Failed = count() by Account, IPAddress, bin(TimeGenerated, 5m)
| where Failed >= 10
```
**MITRE ATT&CK:** T1110 – Brute Force  

---

### 🔹 Suspicious PowerShell Execution  
```kql
SecurityEvent
| where EventID == 4104 or (EventSourceName == "Microsoft-Windows-PowerShell")
| where CommandLine has_any ("EncodedCommand","FromBase64String")
| project TimeGenerated, Account, Computer, CommandLine
```
**MITRE ATT&CK:** T1059 – Command and Scripting Interpreter  

---

### 🔹 Failed RDP Connections  
```kql
SecurityEvent
| where EventID == 4625 and LogonType == 10
| summarize Count = count() by Account, IPAddress, bin(TimeGenerated, 10m)
| where Count > 5
```
**MITRE ATT&CK:** T1021 – Remote Services  

---

## 📊 Example Outputs & Visuals  

**📁 Sample Data:**  
[Download sentinel_sample_4625.csv](https://raw.githubusercontent.com/vagabongo0/Sentinel-KQL-Queries/main/sentinel_sample_4625.csv)  

**🔹 Query Results (Failed Logons)**  
![Sentinel Query](https://raw.githubusercontent.com/vagabongo0/Sentinel-KQL-Queries/main/sentinel_query_4625.png)  
*Sample KQL query and logon failure output.*

**🔹 Brute Force Dashboard**  
![Sentinel Dashboard](https://raw.githubusercontent.com/vagabongo0/Sentinel-KQL-Queries/main/sentinel_dashboard_bruteforce.png)  
*Workbook view showing failed logons by source IP.*

**🔹 Analytics Rule Setup**  
![Analytics Rule](https://raw.githubusercontent.com/vagabongo0/Sentinel-KQL-Queries/main/sentinel_analytic_rule.png)  
*Rule configuration sample for automated alerting (Brute Force).*

---

## 🔖 MITRE ATT&CK Mapping  

| Technique ID | Technique Name | Use Case |
|---------------|----------------|----------|
| **T1110** | Brute Force | Failed logon detection |
| **T1059** | PowerShell Execution | Encoded or obfuscated commands |
| **T1021** | Remote Services | Failed RDP connections |

---

## 🏁 Next Steps  
- Add correlation rules between 4625 → 4624 → PowerShell events.  
- Integrate Defender for Cloud alerts and watchlists.  
- Enrich detections with threat intelligence indicators (TI).  
- Map new detections to ATT&CK tactics: *Credential Access*, *Execution*, *Lateral Movement*.  

---

## 👤 Author  
**Patrick Grant**  
📍 London, UK  
📧 [patrick0grant@proton.me](mailto:patrick0grant@proton.me)  
🔗 [LinkedIn](https://www.linkedin.com/in/patrick-grant-84685338a) | [GitHub](https://github.com/vagabongo0)
