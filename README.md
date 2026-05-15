
# OPERATION STARLIGHT

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized Tor Usage
- [Scenario Creation](https://github.com/PaidDues/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

The Vought cybersecurity team suspects that high profile employees are abusing their access to Vought systems to download and use the Tor browser in order to bypass security controls due to recent network logs showing unusual encrypted traffic from known Tor entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. Vought CEO Mr. Edgar has been made aware of the concern and is asking for a quiet investigation into the matter. Any Tor related activity is to be confirmed, analyzed, and attributed immediately. Mr. Edgar is demanding express and discreet notification on any positive findings!

## Hypothesis

Based on recent network anomalies showing unusual encrypted traffic to known Tor entry nodes
and anonymous internal reports of employees discussing methods to access restricted sites during
work hours, my hypothesis is that one or more employees within the Vought corporate network have
downloaded, installed, and actively used the Tor Browser to bypass organizational security
controls. This hunt will attempt to confirm or refute this hypothesis by examining endpoint
telemetry across file, process, and network event tables in Microsoft Defender for Endpoint.

### High-Level Tor-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known Tor ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table For Confirmation of Tor Being Present

Searched for any file that had the string `tor` in it and discovered what looks like the user `homelander` downloaded a Tor installer, extracted multiple Tor-related files to the desktop, and the creation of a file called `journalist-cowards-tor.txt` on the desktop at `2026-05-01T19:29:55.6369087Z`. These events began at `2026-05-01T19:06:24.866989Z`.

**Query used to locate events:**

```kql
let targetDay = datetime(2026-05-01);
let targetDevice = "vought-lab-01";
let targetUser = "homelander";
DeviceFileEvents
| where Timestamp between (targetDay .. 1d)
    and DeviceName == targetDevice
    and InitiatingProcessAccountName == targetUser
    and FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256
```
<img width="1929" height="583" alt="DeviceFileEvents Screenshot Results (Redux)" src="https://github.com/user-attachments/assets/9d54f5b7-345b-4aff-be36-d00812ad549c" />

---

### 2. Searched the `DeviceProcessEvents` Table For Confirmation of Tor Browser Installation

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2026-05-01T19:08:11.0959154Z`, the user `homelander` on the `vought-lab-01` device ran the file `tor-browser-windows` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
let targetDay = datetime(2026-05-01);
let targetDevice = "vought-lab-01";
let targetUser = "homelander";
DeviceProcessEvents
| where Timestamp between (targetDay .. 1d)
    and DeviceName == targetDevice
    and InitiatingProcessAccountName == targetUser
    and ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1774" height="157" alt="DeviceProcessEvents Screenshot Results (Installer)" src="https://github.com/user-attachments/assets/34b1cad6-0c49-49ad-8869-f278fd6d8c93" />

---

### 3. Searched the `DeviceProcessEvents` Table for Confirmation of Tor Browser Execution

Searched for any indication that user `homelander` actually opened the Tor browser. There was evidence that they did open it at `2026-05-01T19:08:53.2532165Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
let targetDay = datetime(2026-05-01);
let targetDevice = "vought-lab-01";
let targetUser = "homelander";
DeviceProcessEvents
| where Timestamp between (targetDay .. 1d)
    and DeviceName == targetDevice
    and InitiatingProcessAccountName == targetUser
    and FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1929" height="649" alt="DeviceProcessEvents Screenshot Results (execution)" src="https://github.com/user-attachments/assets/f432f69f-f458-4177-ac0b-78a567ec0746" />

---

### 4. Searched the `DeviceNetworkEvents` Table for Confirmation of Tor Network Connections

Searched for any indication the Tor browser was used to establish a connection using any of the known Tor ports. At `2026-05-01T19:09:12.4198138Z`, the user `homelander` on the `vought-lab-01` device successfully established a connection to the remote IP address `146.59.15.186` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\homelander\desktop\tor browser\browser\torbrowser\tor\tor.exe`. Additional connections were observed over port `443`.

**Query used to locate events:**

```kql
let targetDay = datetime(2026-05-01);
let targetDevice = "vought-lab-01";
let targetUser = "homelander";
let torPorts = dynamic([9001, 9030, 9040, 9050, 9051, 9150, 80, 443]);
DeviceNetworkEvents
| where Timestamp between (targetDay .. 1d)
    and DeviceName == targetDevice
    and InitiatingProcessAccountName == targetUser
    and InitiatingProcessFileName in ("tor.exe", "firefox.exe")
    and RemotePort in (torPorts)
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, RemotePort, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath
```
Reasoning: Ports 80 and 443 were intentionally included alongside Tor-specific ports (9001, 9030, 9040, 9050, 9051, 9150) to account for Tor bridge and obfs4 pluggable transport traffic. Tor bridges are unlisted relays that listen on common web ports to blend in with standard HTTPS traffic and evade port-based detection. Because the query also filters by initiating process (tor.exe and firefox.exe) and the results are further validated by folder path (confirming the Tor Browser installation directory), the inclusion of these ports does not introduce significant noise.

<img width="1768" height="355" alt="DeviceNetworkEvents Screenshot Results (Connection)" src="https://github.com/user-attachments/assets/ceeefe59-8243-41e4-940a-8f6a9f30f081" />

---

## MITRE ATT&CK Mapping

| Step | Observed Activity | ATT&CK Technique | Technique ID |
|------|-------------------|-------------------|--------------|
| 1 | Tor installer downloaded to endpoint | Ingress Tool Transfer | T1105 |
| 2 | Silent installation via `/S` flag | User Execution: Malicious File | T1204.002 |
| 3 | Tor Browser and tor.exe launched | Command and Scripting Interpreter | T1059 |
| 4 | Outbound connections to Tor relay on port 9001 | Application Layer Protocol: Web Protocols | T1071.001 |
| 4 | Use of Tor network to anonymize traffic | Proxy: Multi-hop Proxy | T1090.003 |
| 6 | Creation of `journalist-cowards-tor.txt` | Data Staged: Local Data Staging | T1074.001 |

---

## Chronological Event Timeline 

### 1. File Download - Tor Installer

- **Timestamp:** `2026-05-01T19:06:24.866989Z`
- **Event:** The user `homelander` downloaded a file named `tor-browser-windows-x86_64-portable-15.0.11.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\homelander\Downloads\tor-browser-windows-x86_64-portable-15.0.11.exe`

### 2. Process Execution - Tor Browser Installation

- **Timestamp:** `2026-05-01T19:08:11.0959154Z`
- **Event:** The user `homelander` executed the file `tor-browser-windows-x86_64-portable-15.0.11.exe` in silent mode, initiating a background installation of the Tor Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.11.exe /S`
- **File Path:** `C:\Users\homelander\Downloads\tor-browser-windows-x86_64-portable-15.0.11.exe`

### 3. Process Execution - Tor Browser Launch

- **Timestamp:** `2026-05-01T19:08:53.2532165Z`
- **Event:** User `homelander` opened the Tor browser. Subsequent processes associated with Tor browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of Tor browser-related executables detected.
- **File Path:** `C:\Users\homelander\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - Tor Network

- **Timestamp:** `2026-05-01T19:09:12.4198138Z`
- **Event:** A network connection to IP `146.59.15.186` on port `9001` by user `homelander` was established using `tor.exe`, confirming Tor browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\homelander\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - Tor Browser Activity

- **Timestamps:**
  - `2026-05-01T19:09:09.8371751Z` - Connected to `194.164.169.85` on port `443`.
  - `2026-05-01T19:09:21.0603365Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional Tor network connections were established by user `homelander`. The connection to `194.164.169.85` on port `443` is consistent with Tor bridge or obfs4 pluggable transport traffic. The local connection to `127.0.0.1` on port `9150` represents the Tor Browser's built-in SOCKS proxy, a local listener that routes all browser traffic through the Tor network. Both connections confirm active Tor usage.
- **Action:** Multiple successful connections detected.

### 6. File Creation - Plausible Tor-derived List of Journalists

- **Timestamp:** `2026-05-01T19:29:55.6369087Z`
- **Event:** The user `homelander` created a file named `journalist-cowards-tor.txt` on the desktop, potentially indicating a list or notes related to their Tor browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\homelander\Desktop\journalist-cowards-tor.txt`

---

## False Positive Analysis

A key concern in this hunt was distinguishing Tor Browser activity from legitimate Firefox
usage, since the Tor Browser is built on Firefox and shares the same `firefox.exe` process name.

The following factors were used to rule out false positives:

- **Folder Path Validation:** Legitimate Firefox installations reside in
  `C:\Program Files\Mozilla Firefox\`. The `firefox.exe` instances observed in this hunt were
  located in `C:\Users\homelander\Desktop\Tor Browser\Browser\firefox.exe` — a path consistent
  with a portable Tor Browser installation and inconsistent with a standard Firefox deployment.
- **Co-Occurring Processes:** The `firefox.exe` activity was observed alongside `tor.exe`, the
  Tor network daemon. A standard Firefox installation does not launch `tor.exe`.
- **Network Behavior:** The observed connections included traffic over port `9001` to known Tor
  relay IP addresses. Standard Firefox does not generate traffic on Tor-specific ports.
- **Installation Method:** Process execution logs show a silent install (`/S` flag) from a file
  named `tor-browser-windows-x86_64-portable-15.0.11.exe`, confirming the application was the
  Tor Browser, not Firefox.

Based on these indicators, the activity has been confirmed as true positive Tor Browser usage
with high confidence.

---

## Severity & Risk Assessment

| Attribute | Detail |
|-----------|--------|
| **Severity** | High |
| **Confidence** | High — Confirmed via file, process, and network telemetry |
| **User** | homelander |
| **Device** | vought-lab-01 |
| **Policy Violated** | Acceptable Use Policy — Unauthorized software installation and use of anonymizing tools |

**Risk Justification:**

- **Data Exfiltration Risk:** Tor provides encrypted, anonymized communication channels that
  bypass corporate DLP and network monitoring controls, creating an unmonitored pathway for
  sensitive data to leave the organization.
- **Insider Threat Indicator:** The use of a silent installation flag (`/S`) suggests deliberate
  intent to avoid detection, elevating this beyond a casual policy violation.
- **Regulatory Exposure:** Depending on the data accessed, unmonitored browsing through Tor
  could result in compliance violations with applicable data protection regulations.
- **Evidence of Intent:** The creation of `journalist-cowards-tor.txt` suggests targeted activity
  beyond casual browsing, potentially indicating reconnaissance or planning related to media contacts.

---

## Response & Recommendations

**Immediate Actions Taken:**

- The endpoint `vought-lab-01` was isolated from the corporate network via Microsoft Defender
  for Endpoint.
- Mr. Edgar was notified discreetly per the investigation's operational guidelines.
- A snapshot of all relevant telemetry (file, process, and network events) was preserved for
  the investigation record.

**Recommended Next Steps:**

- Disable or suspend the `homelander` user account pending the outcome of the HR and legal review.
- Conduct a forensic review of `journalist-cowards-tor.txt` to determine the nature and
  sensitivity of its contents.
- Run an organization-wide sweep across all endpoints querying for `tor.exe`,
  `tor-browser-windows`, and connections to known Tor relay IPs to determine if additional
  users are affected.
- Update firewall and proxy rules to block connections to known Tor entry and exit nodes using
  published Tor relay lists.
- Submit the Tor installer hash (`SHA256` from the file event logs) to threat intelligence
  platforms to check for any association with known threat actor toolkits.
- Coordinate with HR and Legal to determine appropriate disciplinary or investigative action
  based on the contents of the staged file and the user's browsing activity.

---
