# Suspicious PowerShell Activity Detection

## Overview

This project demonstrates how Splunk can be used to identify suspicious PowerShell activity commonly associated with attacker behavior and post-exploitation techniques.

The investigation focuses on detecting:

* Encoded PowerShell commands
* Execution Policy Bypass attempts
* Hidden PowerShell execution
* Invoke-WebRequest activity
* Potential payload downloads

---

## Objectives

* Analyze PowerShell execution logs
* Detect suspicious command-line patterns
* Perform threat hunting using Splunk SPL
* Develop security monitoring detections
* Map findings to MITRE ATT&CK

---

## Tools Used

* Splunk Enterprise
* CSV Dataset
* Windows PowerShell Logs
* MITRE ATT&CK Framework

---

## Dataset Fields

| Field       | Description      |
| ----------- | ---------------- |
| timestamp   | Event Time       |
| host        | Host Name        |
| user        | User Account     |
| process     | Process Name     |
| commandline | Executed Command |

---

## Detection Queries

### Encoded Commands

```spl
index=powershell commandline="*-enc*"
```

### Execution Policy Bypass

```spl
index=powershell commandline="*ExecutionPolicy Bypass*"
```

### Web Request Activity

```spl
index=powershell commandline="*Invoke-WebRequest*"
```

### Hidden PowerShell Execution

```spl
index=powershell commandline="*Hidden*"
```

### Threat Hunting Query

```spl
index=powershell
(commandline="*-enc*" OR
commandline="*Bypass*" OR
commandline="*Invoke-WebRequest*" OR
commandline="*DownloadString*" OR
commandline="*Hidden*")
| table _time host user commandline
```

---

## Findings

* Encoded PowerShell commands were detected.
* Execution Policy Bypass attempts were observed.
* Hidden PowerShell execution was identified.
* Web request activity was present.
* Multiple suspicious command-line patterns matched common attacker techniques.

---

## MITRE ATT&CK Mapping

| Technique                         | MITRE ID  |
| --------------------------------- | --------- |
| PowerShell                        | T1059.001 |
| Obfuscated Files or Information   | T1027     |
| Command and Scripting Interpreter | T1059     |
| Impair Defenses                   | T1562     |

---

## Skills Demonstrated

* Threat Hunting
* Splunk SPL
* PowerShell Analysis
* Security Monitoring
* Detection Engineering
* MITRE ATT&CK Mapping
* Incident Investigation

---

## Screenshots

Add screenshots for:

* Dataset Creation
* Splunk Data Ingestion
* Encoded Command Detection
* Execution Policy Bypass Detection
* Hidden PowerShell Detection
* Threat Hunting Results
* Alert Configuration

---

## Author

Muhammad Talha

Cybersecurity Student | SOC Analyst in Progress
