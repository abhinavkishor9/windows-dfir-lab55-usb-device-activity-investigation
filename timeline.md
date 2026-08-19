# Timeline — Lab 55 USB Device Activity Investigation

## Timeline Purpose

This timeline records the sequence of USB artifact discovery, Registry investigation, Windows event analysis, storage-state review, user-session correlation, Sysmon analysis, filesystem investigation, and final evidence assessment performed during Lab 55.

The timeline uses the timestamps visible in the collected screenshots where available.

---

# Investigation Timeline

| Order | Time | Source | Activity | Result |
|---:|---|---|---|---|
| 1 | — | Registry | Windows device enumeration tree inspected | `USB` branch identified |
| 2 | — | Registry | `USBSTOR` availability checked | `USBSTOR` unavailable |
| 3 | — | Registry | `Enum\USB` inspected | USB-related entries identified |
| 4 | — | Registry | `DeviceClasses` inspected | Device-interface entries identified |
| 5 | — | Registry | `MountedDevices` investigated | Supporting storage mappings reviewed |
| 6 | — | System Log | Device-provider search performed | No matching events returned |
| 7 | — | System Log | Broad USB message search performed | No matching events returned |
| 8 | 19-08-2026 07:09–07:17 | Event Viewer | System and Security activity reviewed | General Windows activity observed |
| 9 | — | Storage | `Get-Disk` executed | VMware NVMe disk identified |
| 10 | — | Storage | `Get-Volume` executed | Current volume baseline investigated |
| 11 | 19-08-2026 | Security | Event ID 4624 reviewed | Session context investigated |
| 12 | 19-08-2026 07:17:10 | Security | Example Event ID 4624 examined | Logon Type 5 / SYSTEM |
| 13 | 19-08-2026 07:09–07:32 | Sysmon | Event ID 1 reviewed | Process creation telemetry available |
| 14 | 19-08-2026 06:42–07:32 | Sysmon | Event ID 3 reviewed | Network telemetry available |
| 15 | 18-08-2026–19-08-2026 | File System | Recent user files reviewed | Recent filesystem activity identified |
| 16 | — | DFIR Analysis | Evidence sources correlated | USB activity assessment performed |
| 17 | — | DFIR Analysis | Evidence limitations documented | Historical USB connection not established |
| 18 | — | DFIR Analysis | Final assessment completed | USB data transfer not established |

---

# Phase 1 — USB Artifact Discovery

## T+00 — Device Enumeration Baseline

The Windows Registry device enumeration tree was inspected.

Command:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum" |
Select-Object PSChildName
```

The result included:

```text
USB
```

This established that Windows maintains USB-related device enumeration information.

---

## T+05 — USBSTOR Check

The investigation established that the expected `USBSTOR` artifact was unavailable.

No artificial `USBSTOR` entry was created.

This was recorded as an evidence limitation.

---

## T+10 — USB Enumeration Investigation

The following path was examined:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" -ErrorAction SilentlyContinue |
Select-Object PSChildName
```

The endpoint returned:

```text
ROOT_HUB
ROOT_HUB20
ROOT_HUB30
VID_0E0F&PID_0002
VID_0E0F&PID_0003
VID_0E0F&PID_0003&MI_00
VID_0E0F&PID_0003&MI_01
VID_0E0F&PID_0007
VID_0E0F&PID_000A
```

USB-related device enumeration evidence was therefore available.

---

# Phase 2 — Device Interface Investigation

## T+15 — DeviceClasses Investigation

The following Registry path was inspected:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses" -ErrorAction SilentlyContinue |
Select-Object PSChildName
```

Multiple device-interface class GUIDs were returned.

The result demonstrated broader device-interface information but did not independently establish USB storage usage.

---

## T+20 — MountedDevices Investigation

MountedDevices was investigated:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\MountedDevices"
```

The artifact was treated as supporting evidence.

Drive mappings were not automatically attributed to USB devices.

---

# Phase 3 — Windows System Event Investigation

## T+25 — Device Provider Search

The following query was executed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "System"
} -MaxEvents 500 |
Where-Object {
    $_.ProviderName -match "Kernel-PnP|UserPnp|DriverFrameworks"
} |
Select-Object TimeCreated, Id, ProviderName, Message
```

No matching events were returned.

The result was documented as:

> No matching device-provider events were identified in the queried 500-event window.

---

## T+30 — Broad USB Message Search

The following query was executed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "System"
} -MaxEvents 1000 |
Where-Object {
    $_.Message -match "USB|USBSTOR|removable|storage|device"
} |
Select-Object TimeCreated, Id, ProviderName, Message
```

No matching events were returned.

This was documented as a search limitation rather than proof of historical absence.

---

# Phase 4 — Event Viewer Review

## 19-08-2026 07:02:51

A DNS Client Event 1014 was visible in the System log.

The event related to a DNS name-resolution timeout for `wpad`.

It was unrelated to USB activity.

---

## 19-08-2026 07:09:44

Kernel-General Event ID 1 was visible in the System log.

The event represented normal Windows system activity.

No USB attribution was made.

---

## 19-08-2026 07:09:44

Kernel-General Event ID 24 was visible.

The event was treated as general system activity.

---

# Phase 5 — Storage Investigation

## T+40 — Current Disk State

The following command was executed:

```powershell
Get-Disk |
Select-Object Number, FriendlyName, SerialNumber, BusType, Size
```

Result:

```text
Number       : 0
FriendlyName : VMware Virtual NVMe Disk
SerialNumber : VMware NVME_0000
BusType      : NVMe
Size         : 64424509440
```

The endpoint's current disk was identified as a VMware virtual NVMe device.

No current USB storage disk was identified.

---

## T+45 — Current Volume State

Current volumes were investigated using:

```powershell
Get-Volume |
Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, Size
```

The results were treated as current-state storage information.

---

# Phase 6 — User Session Correlation

## 19-08-2026 07:17:10

Security Event ID 4624 was reviewed.

The observed event contained:

```text
Logon Type: 5
Account Name: SYSTEM
```

The event represented a service logon.

It was not treated as evidence of an interactive user performing USB activity.

---

# Phase 7 — Process Activity Investigation

## 19-08-2026 07:09–07:32

Sysmon Event ID 1 was reviewed.

The query returned numerous process creation events.

Observed timestamps included:

```text
07:09
07:11
07:15
07:17
07:19
07:21
07:29
07:30
07:31
07:32
```

Process creation telemetry was therefore available for correlation.

No process was automatically interpreted as evidence of USB activity.

---

# Phase 8 — Network Activity Investigation

## 19-08-2026 06:42–07:32

Sysmon Event ID 3 was reviewed.

Multiple network connection events were present.

Examples occurred at:

```text
06:42
06:44
06:47
06:48
06:49
06:51
06:52
06:53
07:00
07:01
07:04
07:12
07:15
07:18
07:20
07:22
07:25
07:27
07:32
```

The events demonstrated network activity.

They did not establish USB transfer or data exfiltration.

---

# Phase 9 — Filesystem Investigation

## 18-08-2026 — Recent User Files

Recent filesystem activity included:

```text
OneDrive\Documents\Sound Recordings
OneDrive\Pictures\Screenshots
OneDrive\Interview questions.docx
```

The files represented normal recent user activity.

No file was attributed to USB transfer.

---

## 19-08-2026 06:44–07:34 — Screenshot Activity

Multiple screenshot files were created during the investigation timeframe.

Examples included:

```text
Screenshot 2026-08-19 064428.png
Screenshot 2026-08-19 064806.png
Screenshot 2026-08-19 065016.png
Screenshot 2026-08-19 065208.png
Screenshot 2026-08-19 071455.png
Screenshot 2026-08-19 071852.png
Screenshot 2026-08-19 072021.png
Screenshot 2026-08-19 072158.png
Screenshot 2026-08-19 072456.png
Screenshot 2026-08-19 072754.png
Screenshot 2026-08-19 073247.png
Screenshot 2026-08-19 073442.png
```

These files demonstrated active workstation use.

They did not establish removable-media transfer.

---

# Phase 10 — Evidence Correlation

## T+60 — Artifact Evidence Reviewed

The following evidence sources were correlated:

```text
USB Enumeration
        +
DeviceClasses
        +
MountedDevices
        +
System Events
        +
Current Storage
        +
User Session
        +
Sysmon Event ID 1
        +
Sysmon Event ID 3
        +
Filesystem Activity
```

The evidence was assessed according to strength and limitations.

---

## T+65 — Historical USB Connection Assessment

The investigation did not identify sufficient corroborating evidence to establish a historical USB mass-storage connection.

The conclusion remained:

```text
Historical USB connection: Not established
```

---

## T+70 — USB Data Transfer Assessment

No evidence demonstrated:

```text
USB storage device
+
specific user
+
specific file
+
copy operation
```

The conclusion remained:

```text
USB data transfer: Not established
```

---

# Final Timeline Summary

| Phase | Evidence |
|---|---|
| USB Baseline | `USB` Registry branch available |
| USBSTOR | Unavailable |
| USB Enumeration | Multiple USB-related entries identified |
| DeviceClasses | Device-interface information available |
| MountedDevices | Investigated as supporting evidence |
| System Events | No matching USB/device events in queried windows |
| Current Storage | VMware virtual NVMe disk |
| User Session | 4624 available; reviewed example was Logon Type 5 |
| Process Evidence | Sysmon Event ID 1 available |
| Network Evidence | Sysmon Event ID 3 available |
| Filesystem Evidence | Recent user activity available |
| Historical USB Connection | Not established |
| USB Data Transfer | Not established |
| Final Assessment | USB-related artifacts identified, but activity could not be conclusively established |

---

# Investigation Conclusion

The timeline demonstrates the importance of distinguishing USB-related artifact presence from confirmed USB activity.

The endpoint contained USB-related device enumeration information, but the expected `USBSTOR` artifact was unavailable and no matching USB/device System events were identified within the queried event windows.

Current storage state showed a VMware virtual NVMe disk.

Process, network, user-session, and filesystem telemetry provided additional context but did not establish USB-based file transfer.

The final evidence-supported conclusion was:

> **USB-related Windows artifacts were identified, but the available evidence was insufficient to establish a historical USB mass-storage connection or USB data transfer.**

The central DFIR principle demonstrated by this lab is:

> **A strong investigation documents what the evidence proves, what it only supports, and what remains unknown.**
