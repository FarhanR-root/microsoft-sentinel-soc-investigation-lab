# Microsoft Sentinel SOC Investigation Lab

A hands-on Blue Team / Security Operations Center (SOC) investigation lab built using Microsoft Azure, Microsoft Entra ID, Microsoft Sentinel, Log Analytics, KQL, and MITRE ATT&CK.

## Project Overview

This project simulates a SOC investigation involving repeated failed authentication attempts followed by a successful login from the same source IP address.

The objective was to build the detection and investigation workflow from log collection through alert generation, incident investigation, MITRE ATT&CK mapping, dashboard development, and security recommendations.

## Technologies Used

- Microsoft Azure
- Microsoft Entra ID
- Microsoft Sentinel
- Log Analytics
- Kusto Query Language (KQL)
- MITRE ATT&CK

## Lab Architecture

Microsoft Entra ID
        |
        v
   Sign-in Logs
        |
        v
 Log Analytics Workspace
        |
        v
 Microsoft Sentinel
        |
        v
 Analytics Rule
        |
        v
      Alert
        |
        v
     Incident
        |
        v
 Investigation
        |
        v
 MITRE ATT&CK
        |
        v
 Response & Documentation


**#Detection Scenario**

The detection was designed to identify multiple failed authentication attempts against a user account.

Detection threshold:

3 or more failed authentication attempts within a 10-minute window.

**Detection Query**
SigninLogs
| where ResultType == 50126
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 3

Investigation

The investigation focused on:

Identifying the affected account
Identifying the source IP address
Reviewing failed authentication attempts
Checking for successful authentication from the same source
Investigating the application involved
Reviewing available post-login activity
Mapping the observed behavior to MITRE ATT&CK
Key Finding

Multiple failed authentication attempts were observed against the affected account, followed by successful authentication from the same source IP address.

The successful authentication was associated with Azure Portal access.

The investigation also checked Entra ID audit activity for the affected user. No matching audit activity was observed during the investigated period.

The available evidence does not independently confirm account compromise.

MITRE ATT&CK
T1078 — Valid Accounts

T1078 was identified as relevant to the observed authentication behavior because successful authentication occurred using the affected account.

The technique is treated as a relevant mapping rather than proof that compromised credentials were used.

SOC Dashboard

The project includes a Microsoft Sentinel SOC dashboard containing:

Total Sign-ins
Failed Sign-ins
Successful Sign-ins
Sign-ins Over Time
Failed Sign-ins by IP
Failed Sign-ins by User
Sign-ins by Location
Recent Failed Sign-ins
Incident

Incident: Multiple Failed Sign-ins Detection

Severity: Medium

Status: Active

The incident investigation identified a relationship between the affected user account and the source IP address observed during the authentication activity.

**Investigation Workflow**

Log Collection
      ↓
Detection
      ↓
Alert
      ↓
Incident
      ↓
Investigation
      ↓
Correlation
      ↓
MITRE ATT&CK Mapping
      ↓
Response Recommendations
      ↓
Documentation

**Lessons Learned**
This project provided hands-on practice with:

Microsoft Sentinel
KQL-based detection
Authentication log analysis
Incident investigation
Entity mapping
MITRE ATT&CK
SOC dashboard development
Security incident documentation

A key lesson was to distinguish between suspicious authentication activity and confirmed account compromise and to base conclusions on available evidence.

**Evidence**

Screenshots and investigation evidence are included in the repository.

**Disclaimer**

This project was created in a personal Microsoft Azure lab environment for educational and portfolio purposes. The environment does not represent a production SOC.
