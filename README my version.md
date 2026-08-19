# windows-dfir-lab55-usb-device-activity-investigation
## Overview

USB investigations are useful because removable devices can be used for:

Data theft
Malware introduction
Evidence transfer
Unauthorized file copying
Storage of sensitive information

But the important DFIR question is not simply:

“Was a USB device connected?”

Instead, we want to determine:

Was a removable device previously connected, what device was it, when was it connected, which user/session was involved, and is there evidence that files were transferred?

A USB investigation usually involves several layers of evidence:

USB Device
    ↓
Windows Device Detection
    ↓
Registry / Setup Artifacts
    ↓
Device Identification
    ↓
User / Session Correlation
    ↓
File Activity
    ↓
Possible Data Transfer

The investigation examines the USB-related evidence that is actually available on the Windows endpoint and determines what can and cannot be concluded from that evidence.

The investigation focuses on Registry device enumeration, Windows DeviceClasses, MountedDevices, Windows System events, current storage state, user sessions, Sysmon process and network telemetry, and filesystem activity.

The objective is not to manufacture USB evidence or simulate a USB insertion.

The objective is to determine:

> Does this Windows endpoint contain evidence consistent with USB or removable-device activity, and what can be reliably concluded from the available artifacts?

---

# Investigation Objectives

- Determine whether the Windows endpoint contains evidence of USB or removable-device activity.
- Identify available USB-related Registry artifacts, including device enumeration and DeviceClasses.
- Examine MountedDevices for supporting evidence of storage-device usage.
- Analyze Windows System events for device-related activity.
- Review Sysmon process and network telemetry for activity that may provide supporting context.
- Correlate device-related evidence with user sessions and recent file activity.
- Distinguish between current device state, historical device evidence, and evidence of data transfer.
- Avoid treating individual artifacts as definitive proof of USB usage.
- Document artifact limitations, including the absence of USBSTOR.
- Produce a final evidence-based assessment of what USB/removable-device activity can and cannot be established from the available artifacts.

---

# Tools Used

- Windows
- PowerShell
- Windows Registry
- Event Viewer
- Sysmon
- Windows Security Logs
- Windows System Logs
- File System

---

# Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows |
| Investigation Type | Host-Based DFIR |
| Primary Activity | USB and Removable-Device Artifact Investigation |
| Primary Registry Area | `HKLM:\SYSTEM\CurrentControlSet\Enum` |
| USB Enumeration Path | `HKLM:\SYSTEM\CurrentControlSet\Enum\USB` |
| Device Interface Evidence | `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses` |
| Mounted Device Evidence | `HKLM:\SYSTEM\MountedDevices` |
| Primary Event Log | Windows System |
| Process Telemetry | Sysmon Event ID 1 |
| Network Telemetry | Sysmon Event ID 3 |
| Storage Telemetry | `Get-Disk`, `Get-Volume` |
| USBSTOR | Unavailable |

---

# Investigation Scenario

A Windows endpoint has been flagged for possible removable-media usage during routine forensic review.

No confirmed USB insertion event is available, and the commonly referenced USBSTOR Registry location is not present on the system. The analyst therefore cannot rely on a single artifact to determine whether a removable device was used.

The investigation begins by examining the device information that Windows has retained, followed by storage mappings, system activity, logged-on users, process execution, network connections, and recently modified files.

The analyst then correlates these artifacts by timestamp to determine whether they form a consistent sequence of activity involving a removable device.

The investigation aims to establish:

- Whether Windows has recorded USB-related device information.
- Whether the available evidence indicates a removable device was connected.
- Whether the activity can be associated with an interactive user.
- Whether relevant processes or file activity occurred during the same timeframe.
- Whether there is sufficient evidence to support removable-media data transfer.

The investigation will distinguish between device presence, device connection, user activity, and data transfer, rather than treating any single artifact as conclusive proof.

---

# Investigation Workflow

1. Establish the USB artifact baseline.
2. Check the `USBSTOR` path.
3. Investigate the USB device enumeration path.
4. Investigate `DeviceClasses`.
5. Investigate `MountedDevices`.
6. Search Windows System events.
7. Search System event messages for USB references.
8. Review relevant events through Event Viewer.
9. Check current storage devices.
10. Check current volumes.
11. Correlate user sessions.
12. Review Sysmon Event ID 1.
13. Review Sysmon Event ID 3.
14. Investigate recent filesystem activity.
15. Correlate available evidence.
16. Separate direct evidence from supporting evidence.
17. Document telemetry gaps.
18. Produce a final USB activity assessment.

---

# Step 1 — Establish USB Artifact Baseline

The first step was to inspect the Windows device enumeration tree.

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum" |
Select-Object PSChildName
```

The result included:

```text
ACPI
ACPI_HAL
DISPLAY
FDC
HDAUDIO
HID
HTREE
PCI
PCIIDE
ROOT
SCSI
STORAGE
SWD
USB
```

The presence of the `USB` branch confirmed that Windows maintains USB-related device enumeration information.

---

# Step 2 — Check USBSTOR

The expected USB mass-storage Registry path was checked.

The investigation confirmed that:

`USBSTOR`

was unavailable on this endpoint.

The artifact was not created or modified for the purpose of the lab.

This is an important limitation.

The absence of `USBSTOR` does not by itself prove that USB activity never occurred.

---

# Step 3 — Investigate USB Device Enumeration

The following Registry path was investigated:

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

This demonstrates that USB-related device enumeration information exists on the system.

However, the presence of a `VID_xxxx&PID_xxxx` entry does not automatically prove that the entry represents a removable USB storage device.

The artifact must therefore be interpreted carefully.

---

# Step 4 — Investigate DeviceClasses

The following Registry path was examined:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses" -ErrorAction SilentlyContinue |
Select-Object PSChildName
```

Multiple device-interface class GUIDs were returned.

This confirms that Windows maintains broader device-interface information.

However, the presence of DeviceClasses entries alone does not identify a USB flash drive or prove a historical USB connection.

DeviceClasses therefore provides supporting artifact context rather than standalone proof of USB storage activity.

---

# Step 5 — Investigate MountedDevices

The MountedDevices Registry key was investigated using:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\MountedDevices"
```

Mounted device mappings can provide useful information about drive-letter and device associations.

However, a drive-letter mapping must not automatically be interpreted as evidence of a USB device.

A drive letter may represent:

- Internal storage.
- Virtual storage.
- Network-mounted resources.
- Removable storage.
- Other Windows-managed volumes.

Therefore, MountedDevices should be correlated with other artifacts before making a USB attribution.

---

# Step 6 — Investigate Windows System Events

The first System event query searched for common device-related providers:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "System"
} -MaxEvents 500 |
Where-Object {
    $_.ProviderName -match "Kernel-PnP|UserPnp|DriverFrameworks"
} |
Select-Object TimeCreated, Id, ProviderName, Message
```

No matching events were returned in the queried 500-event window.

This does not establish that the endpoint has never generated device-related events.

It only establishes that matching events were not present in the specific event subset searched.

---

# Step 7 — Broad USB Message Search

A broader search was then performed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "System"
} -MaxEvents 1000 |
Where-Object {
    $_.Message -match "USB|USBSTOR|removable|storage|device"
} |
Select-Object TimeCreated, Id, ProviderName, Message
```

No matching events were returned from the queried 1000 System events.

This result is documented as an evidence limitation rather than proof of absence.

---

# Step 8 — Event Viewer Review

Windows Event Viewer was reviewed directly.

The System log contained normal Windows system activity, including examples such as:

- DNS Client Events
- Kernel-General
- Time-Service

A DNS Client Event 1014 was visible during the review.

The observed event was unrelated to USB activity.

No direct USB device insertion event was identified during the reviewed evidence.

---

# Step 9 — Current Storage Device Investigation

Current disks were examined using:

```powershell
Get-Disk |
Select-Object Number, FriendlyName, SerialNumber, BusType, Size
```

The endpoint returned:

```text
Number       : 0
FriendlyName : VMware Virtual NVMe Disk
SerialNumber : VMware NVME_0000
BusType      : NVMe
Size         : 64424509440
```

The current storage device was identified as a VMware virtual NVMe disk.

No current USB storage disk was identified.

This is current-state evidence only.

It cannot prove that a USB device was never connected in the past.

---

# Step 10 — Volume Investigation

Volumes were also examined:

```powershell
Get-Volume |
Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, Size
```

The purpose was to determine how Windows currently identifies available volumes.

Current volume information is supporting evidence and should not independently be used to establish historical USB activity.

---

# Step 11 — User Session Correlation

Windows Security Event ID 4624 was reviewed.

The Security log contained many successful logon events.

An example event showed:

```text
Event ID: 4624
Logon Type: 5
Account Name: SYSTEM
```

The observed event represented a service logon rather than an interactive user logon.

This is important because not every 4624 event represents a human user interacting with the workstation.

A USB connection should not automatically be attributed to a user based only on the presence of a 4624 event.

---

# Step 12 — Sysmon Event ID 1

Sysmon Event ID 1 was queried:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 200 |
Select-Object TimeCreated, Id, Message
```

The endpoint contained numerous process creation events.

The observed timestamps included activity around:

```text
19-08-2026 07:32
19-08-2026 07:31
19-08-2026 07:30
19-08-2026 07:29
19-08-2026 07:21
19-08-2026 07:19
19-08-2026 07:17
```

Sysmon Event ID 1 provides process-level telemetry.

Relevant processes can be investigated when they occur around a device-related timeframe.

Examples include:

- `explorer.exe`
- `powershell.exe`
- `cmd.exe`
- `robocopy.exe`
- `xcopy.exe`

However, process presence alone does not prove that files were copied to a USB device.

---

# Step 13 — Sysmon Event ID 3

Sysmon Event ID 3 was queried:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 200 |
Select-Object TimeCreated, Id, Message
```

Numerous network connection events were available.

The results showed repeated network activity during the investigation timeframe.

Network activity is supporting evidence only.

A network connection does not independently prove:

- USB activity.
- File copying.
- Data exfiltration.
- Malicious activity.

If a future investigation identifies USB evidence plus suspicious file activity and a network connection, the combined evidence could justify deeper investigation.

---

# Step 14 — Filesystem Activity

Recent files under `C:\Users` were investigated:

```powershell
Get-ChildItem "C:\Users" -File -Recurse -ErrorAction SilentlyContinue |
Sort-Object LastWriteTime -Descending |
Select-Object -First 50 FullName, Length, LastWriteTime
```

The most recent activity consisted primarily of:

- Screenshots.
- OneDrive files.
- Sound recordings.
- Interview-related documents.
- OneDrive shortcut activity.

Examples included:

```text
C:\Users\[user]\OneDrive\Pictures\Screenshots\
C:\Users\[user]\OneDrive\Documents\Sound Recordings\
C:\Users\[user]\OneDrive\Interview questions.docx
```

These files demonstrate recent filesystem activity but do not establish removable-media transfer.

The investigation did not simulate copying these files to a USB device.

---

# Evidence Correlation

The investigation followed this evidence model:

```text
USBSTOR unavailable
        |
        v
USB Enumeration Available
        |
        v
DeviceClasses Available
        |
        v
System USB/Device Event Search
        |
        v
No Matching Events in Queried Windows
        |
        v
MountedDevices
        |
        v
Current Storage State
        |
        v
User Session Context
        |
        v
Sysmon Process Activity
        |
        v
Filesystem Activity
        |
        v
Sysmon Network Activity
        |
        v
Final Evidence Assessment
```

The objective was to determine the strongest conclusion supported by the available evidence.

---


# MITRE ATT&CK Relevance

This investigation can support analysis related to:

**T1200 — Hardware Additions**

where evidence supports unauthorized hardware being added to a system.

Removable-media investigations may also contribute to broader data-exfiltration investigations when combined with evidence of file access and transfer.

However, no ATT&CK technique should be asserted solely because a USB Registry artifact exists.

Technique mapping should be based on observed behavior and corroborating evidence.

---


# Disclaimer

This investigation was performed in a controlled Windows environment.

No USB evidence was artificially created.

No Windows event logs, system files, security controls, or recovery infrastructure were intentionally modified or deleted.

The investigation focuses on interpreting artifacts that were already available on the endpoint and documenting evidence limitations.
