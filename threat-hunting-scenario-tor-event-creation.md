# Threat Event (Unauthorized Tor Usage)
**Unauthorized Tor Browser Installation and Use**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Download the Tor browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-15.0.11.exe /S```
3. Opens the Tor browser from the folder on the desktop
4. Connect to Tor and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a file on your desktop called ```journalist-cowards-tor.txt``` and put a few fake journalist names in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used for detecting Tor download and installation, as well as the journalist list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Used to detect the silent installation of Tor as well as the Tor browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect Tor network activity, specifically tor.exe and firefox.exe making connections over ports to be used by Tor (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// Tor Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.11.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// Tor Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// Tor Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Tor Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User journalist list was created, changed, and then deleted
DeviceFileEvents
| where FileName contains "journalist-cowards-tor"
```

---

## Created By:
- **Author Name**: Max Dues
- **Author Contact**: https://www.linkedin.com/in/mdues/
- **Date**: May 01, 2026

---

## Additional Notes:
- **None currently**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `May 01, 2026`  | `Max Dues`   
