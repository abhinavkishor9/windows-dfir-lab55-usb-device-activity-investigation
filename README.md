# Windows DFIR Lab 55 — USB Device Activity Investigation

## Overview

USB investigations are often approached with the assumption that a `USBSTOR` Registry artifact must exist and that its absence means no USB activity occurred.

This lab takes a different approach.

The investigation examines the USB-related evidence that is actually available on the Windows endpoint and determines what can and cannot be concluded from that evidence.

The investigation focuses on Registry device enumeration, Windows DeviceClasses, MountedDevices, Windows System events, current storage state, user sessions, Sysmon process and network telemetry, and filesystem activity.

The objective is not to manufacture USB evidence or simulate a USB insertion.

The objective is to determine:

> Does this Windows endpoint contain evidence consistent with USB or removable-device activity, and what can be reliably concluded from the available artifacts?

---

# Executive Summary

The Windows endpoint did not contain the expected `USBSTOR` Registry path used to investigate USB mass-storage devices.

However, the investigation confirmed that Windows maintains USB-related device enumeration information.

The Registry path:

`HKLM:\SYSTEM\CurrentControlSet\Enum\USB`

was available and contained entries including:

- `ROOT_HUB`
- `ROOT_HUB20`
- `ROOT_HUB30`
- `VID_0E0F&PID_0002`
- `VID_0E0F&PID_0003`
- `VID_0E0F&PID_0003&MI_00`
- `VID_0E0F&PID_0003&MI_01`
- `VID_0E0F&PID_0007`
- `VID_0E0F&PID_000A`

The broader device enumeration path also contained a `USB` branch.

Windows `DeviceClasses` information was available, demonstrating that the operating system maintains device-interface information.

The System event searches did not return matching `Kernel-PnP`, `UserPnp`, or `DriverFrameworks` provider events within the queried event windows. A broader message search for USB, USBSTOR, removable, storage, and device references also returned no results in the queried event window.

The current storage state showed one disk:

`VMware Virtual NVMe Disk`

with:

`BusType = NVMe`

No current USB storage disk was identified by `Get-Disk`.

Sysmon Event ID 1 and Event ID 3 were available and were reviewed as supporting endpoint telemetry. Filesystem activity was also examined, but no controlled USB transfer was performed.

The investigation therefore did not establish that a physical USB mass-storage device was historically connected, and it did not establish USB-based data transfer or data theft.

---

# Investigation Objectives

- Determine whether USB-related Registry artifacts are available.
- Establish whether the `USBSTOR` Registry path exists.
- Investigate the Windows USB enumeration path.
- Examine `DeviceClasses` for broader device-interface information.
- Investigate `MountedDevices`.
- Search Windows System events for device-related activity.
- Search System event messages for USB and removable-media references.
- Examine current storage devices and their bus types.
- Examine current volumes and drive types.
- Review interactive user-session information.
- Review Sysmon process creation telemetry.
- Review Sysmon network telemetry.
- Examine recent filesystem activity for supporting context.
- Correlate available artifacts without over-attributing evidence.
- Determine whether USB connection activity can be supported.
- Determine whether USB data transfer can be supported.
- Document evidence gaps and limitations.

---

# Skills Demonstrated

- Windows DFIR
- USB Artifact Investigation
- Removable Media Investigation
- Windows Registry Analysis
- Device Enumeration Analysis
- DeviceClasses Analysis
- MountedDevices Analysis
- Windows Event Log Investigation
- Event Viewer Investigation
- Sysmon Event ID 1 Analysis
- Sysmon Event ID 3 Analysis
- Filesystem Timeline Analysis
- User Session Correlation
- Evidence Correlation
- Artifact Validation
- DFIR Evidence Limitation Documentation
- Historical vs Current State Analysis

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

A Windows workstation is being investigated for possible removable-media activity.

The analyst does not have a confirmed USB insertion event and the expected `USBSTOR` Registry artifact is unavailable.

Instead of assuming that no USB activity occurred, the analyst performs an artifact-discovery investigation.

The investigation examines available Registry artifacts, device interfaces, mounted-device information, Windows System events, current storage state, user sessions, process activity, network activity, and filesystem activity.

The objective is to determine whether the available evidence supports:

1. USB-related device presence.
2. A historical USB connection.
3. A specific user association.
4. File activity associated with removable media.
5. USB-based data transfer.

Each conclusion must be supported by evidence.

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

# Observed Evidence

| Evidence Source | Result | Interpretation |
|---|---|---|
| `USBSTOR` | Unavailable | USB mass-storage artifact unavailable |
| `Enum\USB` | Available | USB-related device enumeration exists |
| `DeviceClasses` | Available | Device-interface information exists |
| System device-provider search | No matches | No matching events in queried window |
| Broad USB System search | No matches | No matching messages in queried window |
| MountedDevices | Investigated | Supporting drive/device information |
| `Get-Disk` | NVMe disk | No current USB storage disk identified |
| `Get-Volume` | Investigated | Current volume baseline |
| Security 4624 | Available | Session context available |
| Sysmon 1 | Available | Process telemetry available |
| Sysmon 3 | Available | Network telemetry available |
| Filesystem | Recent activity available | Supporting context only |

---

# Evidence Classification

## Level 1 — USB-Related Evidence Identified

Supported.

The system contains USB-related Registry enumeration information under:

`HKLM:\SYSTEM\CurrentControlSet\Enum\USB`

and contains USB-related entries such as:

`ROOT_HUB`

and:

`VID_0E0F&PID_0003`

This establishes the presence of USB-related device enumeration artifacts.

---

## Level 2 — Historical USB Connection Supported

Not established.

The investigation did not identify sufficient evidence to confidently state that a removable USB storage device was connected during a specific historical timeframe.

The absence of `USBSTOR` and matching System events limits the strength of the historical connection assessment.

---

## Level 3 — USB Data Transfer Supported

Not established.

The investigation did not produce evidence demonstrating:

```text
USB storage device
        +
specific user
        +
specific file activity
        +
copy/transfer operation
```

Therefore, USB-based data transfer or data theft cannot be concluded.

---

# Key Findings

- `USBSTOR` was unavailable on the endpoint.
- The `Enum` Registry tree contained a `USB` branch.
- The USB enumeration path contained multiple device identifiers.
- `DeviceClasses` contained numerous device-interface class entries.
- No matching Kernel-PnP, UserPnp, or DriverFrameworks events were returned from the queried System event subset.
- No matching USB, USBSTOR, removable, storage, or device messages were returned from the broader queried System event subset.
- The current disk state showed a VMware virtual NVMe disk.
- No current USB storage disk was identified.
- Security Event ID 4624 was available for session correlation.
- The reviewed 4624 example was Logon Type 5 and represented SYSTEM service activity rather than an interactive user session.
- Sysmon Event ID 1 was available for process investigation.
- Sysmon Event ID 3 was available for network investigation.
- Recent filesystem activity was identified.
- Filesystem activity did not establish USB transfer.
- Network activity did not establish USB transfer or exfiltration.
- No controlled USB insertion or file-copy simulation was performed.
- No USB evidence was artificially created.

---

# DFIR Interpretation

The most important distinction in this investigation is:

```text
USB-related artifact exists
```

versus:

```text
USB mass-storage device was connected
```

and:

```text
Files were transferred to the USB device
```

These are three different investigative conclusions.

The presence of USB enumeration artifacts demonstrates that Windows maintains USB-related device information.

It does not automatically identify a USB flash drive, establish a historical connection time, identify a user, or prove file transfer.

Likewise, the absence of `USBSTOR` should be treated as a limitation rather than proof that USB activity never occurred.

---

# MITRE ATT&CK Relevance

This investigation can support analysis related to:

**T1200 — Hardware Additions**

where evidence supports unauthorized hardware being added to a system.

Removable-media investigations may also contribute to broader data-exfiltration investigations when combined with evidence of file access and transfer.

However, no ATT&CK technique should be asserted solely because a USB Registry artifact exists.

Technique mapping should be based on observed behavior and corroborating evidence.

---

# Evidence Limitations

The investigation had several limitations.

`USBSTOR` was unavailable on the endpoint.

The System event searches did not identify matching USB/device events in the queried event windows.

Current `Get-Disk` information represents the present storage state and cannot prove historical absence of USB devices.

Device enumeration entries do not automatically identify removable storage.

DeviceClasses entries provide supporting device-interface information but do not independently prove USB storage usage.

Security Event ID 4624 provides session context but does not automatically associate a user with a USB device.

Sysmon Event ID 1 provides process telemetry but does not prove that a process accessed USB storage.

Sysmon Event ID 3 provides network telemetry but does not prove data exfiltration.

Filesystem timestamps do not establish that files were copied to removable media.

No physical USB device was intentionally connected for this lab.

---

# Final Assessment

The investigation identified genuine USB-related Windows device enumeration artifacts, but the available evidence was insufficient to establish a historical USB mass-storage connection or USB-based data transfer.

The strongest evidence-supported conclusion is:

> Windows contains USB-related device enumeration artifacts, but the available artifacts do not reliably establish that a removable USB storage device was connected during a specific historical timeframe or that data was transferred to such a device.

This is an evidence-limited finding rather than a failed investigation.

The lab demonstrates an important DFIR principle:

> **Artifact presence is not the same as activity proof.**

A strong investigator must distinguish between what the artifact proves, what it supports, and what remains unknown.

---

# Disclaimer

This investigation was performed in a controlled Windows environment.

No USB evidence was artificially created.

No Windows event logs, system files, security controls, or recovery infrastructure were intentionally modified or deleted.

The investigation focuses on interpreting artifacts that were already available on the endpoint and documenting evidence limitations.
