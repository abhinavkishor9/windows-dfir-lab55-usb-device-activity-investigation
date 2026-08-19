# Investigation Notes — Lab 55 USB Device Activity Investigation

## Investigation Overview

The investigation focused on determining whether the Windows endpoint contained evidence of USB or removable-device activity and what could reliably be concluded from the available artifacts.

The expected `USBSTOR` Registry artifact was unavailable.

Instead of creating the missing artifact or simulating a USB connection, the investigation examined alternative Windows artifacts including USB device enumeration, DeviceClasses, MountedDevices, System events, current storage state, user sessions, Sysmon telemetry, and filesystem activity.

---

## Investigation Question

The primary investigation question was:

> Does this Windows endpoint contain evidence of USB/removable-device activity, and what can be reliably concluded from the available artifacts?

The investigation deliberately separated:

- USB-related artifact presence.
- Historical USB connection evidence.
- User attribution.
- File activity.
- USB data transfer evidence.

---

## USBSTOR Availability

The investigation established that the expected USB mass-storage artifact was unavailable.

`USBSTOR` was not present.

This was documented as an artifact limitation.

The artifact was not created or modified for the purpose of the investigation.

The absence of `USBSTOR` was not interpreted as proof that USB activity never occurred.

---

## USB Enumeration

The broader device enumeration tree was inspected:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum" |
Select-Object PSChildName
```

The result included:

```text
USB
```

The USB-specific path was then investigated:

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

This confirmed the availability of USB-related device enumeration information.

However, the entries were not automatically interpreted as USB mass-storage devices.

---

## DeviceClasses Investigation

The following Registry path was examined:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses" -ErrorAction SilentlyContinue |
Select-Object PSChildName
```

Multiple device-interface class GUIDs were returned.

This established that Windows maintains device-interface information.

DeviceClasses was treated as supporting evidence.

The presence of DeviceClasses entries alone was not considered sufficient to establish removable-media usage.

---

## MountedDevices Investigation

MountedDevices was investigated using:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\MountedDevices"
```

MountedDevices can provide useful drive and device mapping information.

However, drive-letter mappings were not automatically attributed to USB devices.

The artifact was therefore treated as supporting evidence that requires correlation.

---

## Windows System Event Investigation

The first query searched for common device-related providers:

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

No matching events were returned from the queried event windows.

This was recorded as:

> No matching USB/device System events were identified in the queried event windows.

It was not recorded as:

> No USB activity ever occurred.

---

## Event Viewer Investigation

The Windows System log was reviewed directly through Event Viewer.

The System log contained normal Windows activity.

Examples included:

- DNS Client Events.
- Kernel-General.
- Time-Service.

A DNS Client Event 1014 was visible.

The observed event was unrelated to USB activity.

No direct USB insertion event was identified during the reviewed evidence.

---

## Current Storage Investigation

Current storage devices were investigated using:

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

The current disk was therefore identified as a VMware virtual NVMe disk.

No current USB storage disk was identified.

This was treated as current-state evidence.

---

## Volume Investigation

Current volumes were investigated using:

```powershell
Get-Volume |
Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, Size
```

The purpose was to establish the current storage and volume baseline.

Current volume information cannot independently prove or disprove historical USB usage.

---

## User Session Investigation

Security Event ID 4624 was reviewed.

The Security log contained numerous successful logon events.

One reviewed event showed:

```text
Event ID: 4624
Logon Type: 5
Account Name: SYSTEM
```

Logon Type 5 represents a service logon.

It therefore did not provide evidence of a human user interactively accessing the workstation at that timestamp.

User attribution was not made from this event.

---

## Sysmon Event ID 1

Sysmon Event ID 1 was available:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 200 |
Select-Object TimeCreated, Id, Message
```

Numerous process creation events were returned.

The events occurred throughout the investigation timeframe.

Sysmon Event ID 1 was treated as supporting process telemetry.

Relevant processes could potentially be correlated with removable-media activity if stronger USB evidence were available.

Process creation alone does not prove USB access.

---

## Sysmon Event ID 3

Sysmon Event ID 3 was available:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 200 |
Select-Object TimeCreated, Id, Message
```

Numerous network connection events were returned.

The network events were treated as supporting evidence only.

A network connection does not establish:

- USB usage.
- File copying.
- Data exfiltration.
- Malicious activity.

---

## Filesystem Investigation

Recent filesystem activity was examined:

```powershell
Get-ChildItem "C:\Users" -File -Recurse -ErrorAction SilentlyContinue |
Sort-Object LastWriteTime -Descending |
Select-Object -First 50 FullName, Length, LastWriteTime
```

The most recent files included screenshots, OneDrive files, sound recordings, and documents.

Examples included:

```text
OneDrive\Pictures\Screenshots
OneDrive\Documents\Sound Recordings
OneDrive\Interview questions.docx
```

This demonstrated recent filesystem activity.

However, no evidence established that these files were copied to removable media.

---

## Evidence Correlation

The evidence chain was treated as:

```text
USBSTOR unavailable
        |
        v
USB Enumeration available
        |
        v
DeviceClasses available
        |
        v
System event searches
        |
        v
No matching events in queried windows
        |
        v
Current storage state
        |
        v
User/session context
        |
        v
Process activity
        |
        v
Filesystem activity
        |
        v
Network activity
        |
        v
Final assessment
```

Each artifact was interpreted according to its actual evidentiary value.

---

## Evidence Classification

### USB-Related Artifact Evidence

**Supported.**

USB-related Registry enumeration information exists.

### Historical USB Connection

**Not established.**

The available evidence does not reliably identify a historical removable USB storage connection.

### Specific User Attribution

**Not established.**

The reviewed session evidence did not establish a user-to-USB association.

### File Activity

**Observed.**

Recent filesystem activity was present.

### USB Data Transfer

**Not established.**

No evidence demonstrated that files were copied to a USB storage device.

---

## Key Findings

1. `USBSTOR` was unavailable.
2. The Windows Registry contained a `USB` enumeration branch.
3. USB enumeration contained multiple device identifiers.
4. DeviceClasses information was available.
5. No matching device-provider events were returned from the queried System event window.
6. No matching USB-related messages were returned from the broader System search.
7. Current storage was identified as a VMware virtual NVMe disk.
8. No current USB storage disk was identified.
9. Security Event ID 4624 was available for session context.
10. The reviewed 4624 event represented a SYSTEM service logon.
11. Sysmon Event ID 1 was available.
12. Sysmon Event ID 3 was available.
13. Recent filesystem activity was observed.
14. Filesystem activity did not establish USB transfer.
15. Network activity did not establish data exfiltration.
16. Historical USB mass-storage usage was not proven.
17. USB data transfer was not proven.

---

## Analyst Assessment

The endpoint contains USB-related device enumeration artifacts.

However, the available evidence does not provide enough corroboration to conclude that a USB mass-storage device was historically connected during a specific timeframe.

The evidence also does not support a conclusion that data was copied to a USB device.

The investigation therefore demonstrates the importance of separating:

```text
Artifact presence
```

from:

```text
Activity evidence
```

and:

```text
Confirmed user action
```

---

## Final Assessment

The strongest evidence-supported conclusion is:

> Windows contains USB-related device enumeration artifacts, but the available evidence is insufficient to establish a historical USB mass-storage connection or USB-based data transfer.

The investigation is therefore classified as an **artifact availability and evidence-validation investigation** rather than a confirmed USB incident.
